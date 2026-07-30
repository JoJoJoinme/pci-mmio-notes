from __future__ import annotations

import base64
import copy
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from qman_directpath_core.canonical import (
    canonical_json_bytes,
    sha256_digest,
)
from qman_directpath_core.contracts import ContractSchemas
from qman_directpath_core.errors import DirectPathVerificationError
from qman_directpath_core.inventory import (
    derive_device_provider_facts_digest,
)
from qman_directpath_core.policy import verify_capability_policy
from qman_directpath_core.publication_capture import (
    DEFAULT_PUBLICATION_CAPTURE_LIMITS,
    HOST_SNAPSHOT_CAPTURE_AUTHORITY_BOUNDARY,
    HOST_SNAPSHOT_CAPTURE_BATCH_ARTIFACT_SCHEMA_REF,
    HOST_SNAPSHOT_CAPTURE_PRODUCT_EVIDENCE_BLOCKERS,
    HOST_SNAPSHOT_PROVIDER_OUTPUT_SCHEMA_REF,
    HOST_SNAPSHOT_PROVIDER_SEMANTIC_FACTS_SCHEMA_REF,
    PublicationCaptureVerifierLimits,
    VerifiedHostSnapshotCaptureClosureContext,
    replay_host_snapshot_capture_closure,
    verify_host_snapshot_capture_closure,
)
from qman_directpath_core.snapshot_semantics import (
    derive_host_snapshot_semantics,
    derive_no_change_projection,
)
from tests.test_inventory import (
    CAPTURE_STARTED_AT,
    CAPTURED_AT,
    InventoryFixture,
)


ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "contracts"
CAPTURE_BATCH_DOMAIN = b"QMAN-DIRECTPATH/HOST-CAPTURE-BATCH/V1\x00"
FRESHNESS_POLICY_DOMAIN = b"QMAN-DIRECTPATH/HOST-SNAPSHOT-FRESHNESS-POLICY/V1\x00"
PROVIDER_SEMANTIC_DOMAIN = b"QMAN-DIRECTPATH/PROVIDER-SEMANTIC-FACTS/V1\x00"
VERIFY_AT = datetime(2026, 7, 24, 2, 0, 0, tzinfo=timezone.utc)


def digest(label: str) -> str:
    return sha256_digest(label.encode("utf-8"))


def encode(document: dict) -> str:
    return base64.b64encode(canonical_json_bytes(document)).decode("ascii")


def decoded(encoded: str) -> dict:
    return json.loads(base64.b64decode(encoded))


def thaw(value):
    if isinstance(value, dict) or hasattr(value, "items"):
        return {key: thaw(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [thaw(item) for item in value]
    return value


def capability_policy_document(*, version: int = 7) -> dict:
    document = {
        "subjectType": "DIRECTPATH_CAPABILITY_POLICY",
        "schemaVersion": 1,
        "policyId": "directpath-publication-policy",
        "policyVersion": version,
        "admissionMode": "PRODUCTION",
        "supportedCatalogDigest": digest("catalog"),
        "catalogSequence": 11,
        "trustKeyRingSequence": 13,
        "qualificationCaseMatrixHash": digest("case-matrix"),
        "dependencyClosure": {
            "resolverAlgorithmId": "SEVEN_DOMAIN_RESET_FIXED_POINT_V1",
            "maxDevices": 256,
            "maxEdges": 4096,
        },
        "sourceCompatibilityProfilePolicyDigest": digest(
            "compatibility-profile-policy"
        ),
        "effectiveAt": "2026-07-24T01:00:00.000000Z",
        "expiresAt": "2026-07-24T03:00:00.000000Z",
        "policyHash": None,
    }
    document["policyHash"] = sha256_digest(canonical_json_bytes(document))
    return document


class PublicationFixture:
    def __init__(
        self,
        *,
        generic_provider: bool = False,
        unavailable_pci: bool = False,
        pci_observed_at: str = CAPTURED_AT,
        two_devices: bool = False,
        maximum_evidence_age_micros: int = 2_000_000,
    ) -> None:
        self.schemas = ContractSchemas(CONTRACTS)
        self.inventory = InventoryFixture()
        if two_devices:
            identity = copy.deepcopy(self.inventory.identity)
            identity["physicalPath"] = "acpi:/_SB_/PCI0/RP06#adr=0000000000000000"
            self.inventory.records.append(
                InventoryFixture.make_record(identity, "0000:02:00.0")
            )
        for record in self.inventory.records:
            raw = bytes.fromhex(
                record["role"]["pciStructureFact"]["rawConfigSpaceHexOrNull"]
            )
            if unavailable_pci:
                self.inventory.bind_pci_capture(
                    record,
                    None,
                    failure_reason_code="PCI_CONFIG_READ_FAILED",
                    observed_at=pci_observed_at,
                )
                record["role"]["structuralRole"] = "UNKNOWN"
                record["resetContract"]["state"] = "UNKNOWN"
                record["resetContract"]["supported"] = False
                record["resetContract"]["selectedMethodOrNull"] = None
                record["resetContract"]["resetAffectedSet"] = []
            elif pci_observed_at != CAPTURED_AT:
                self.inventory.bind_pci_capture(
                    record,
                    raw,
                    observed_at=pci_observed_at,
                )
            if generic_provider:
                record["provenance"]["providerFacts"].append(
                    {
                        "factId": f"generic-owner-{record['currentBdf']}",
                        "providerId": "linux-owner-provider",
                        "providerVersion": 1,
                        "providerDefinitionDigest": digest("owner-provider-definition"),
                        "observedAt": CAPTURED_AT,
                        "evidenceHash": digest(
                            f"owner-evidence-{record['currentBdf']}"
                        ),
                    }
                )
                record["provenance"]["providerFacts"].sort(
                    key=lambda item: canonical_json_bytes(
                        [
                            item["factId"],
                            item["providerId"],
                            item["providerVersion"],
                            item["evidenceHash"],
                        ]
                    )
                )
            # Publication artifacts are the final committed-row candidates.
            # Their internally stamped device generation must already be
            # composable with the full publication contract.
            record["generations"]["deviceGeneration"] = record["generations"][
                "snapshotEpoch"
            ]
        self.inventory.records.sort(
            key=lambda item: canonical_json_bytes(item["deviceUid"])
        )
        self.inventory.reseal()
        self.capability_policy = verify_capability_policy(
            self.schemas,
            capability_policy_document(),
            verified_at=VERIFY_AT,
        )
        first_pci_fact = self._pci_fact(self.inventory.records[0])
        self.freshness_policy = {
            "subjectType": "HOST_SNAPSHOT_FRESHNESS_POLICY",
            "schemaVersion": 1,
            "policyId": "host-snapshot-freshness",
            "policyVersion": 1,
            "maximumSnapshotAgeMicros": 60_000_000,
            "maximumMandatoryEvidenceAgeMicros": (maximum_evidence_age_micros),
            "mandatoryProviderFacts": [
                {
                    "providerId": first_pci_fact["providerId"],
                    "factId": first_pci_fact["factId"],
                }
            ],
            "policyHash": None,
        }
        self.reseal_freshness_policy(rederive_batch=False)
        self.device_record_artifacts = self._device_artifacts()
        self.batch = self._capture_batch()
        self.rederive_projections()
        self.reseal_batch()

    @staticmethod
    def _provider_key(fact: dict) -> tuple[str, int, str]:
        return (
            fact["providerId"],
            fact["providerVersion"],
            fact["providerDefinitionDigest"],
        )

    @staticmethod
    def _pci_fact(record: dict) -> dict:
        fact_id = record["role"]["pciStructureFact"]["providerFactId"]
        return next(
            item
            for item in record["provenance"]["providerFacts"]
            if item["factId"] == fact_id
        )

    def _device_artifacts(self) -> list[dict]:
        artifacts: list[dict] = []
        for record in self.inventory.records:
            generations = record["generations"]
            raw = canonical_json_bytes(record)
            artifacts.append(
                {
                    "schemaRef": (
                        "contracts/directpath-portable-entities.schema.json"
                        "#/$defs/ENTITY-DEVICE-RECORD"
                    ),
                    "recordBinding": {
                        "hostId": record["hostId"],
                        "deviceUid": record["deviceUid"],
                        "hostEpoch": generations["hostEpoch"],
                        "agentGeneration": generations["agentGeneration"],
                        "snapshotEpoch": generations["snapshotEpoch"],
                        "deviceGeneration": generations["deviceGeneration"],
                        "resourceVersion": generations["resourceVersion"],
                        "deviceRecordHash": record["deviceRecordHash"],
                    },
                    "canonicalInstanceBase64": base64.b64encode(raw).decode("ascii"),
                    "instanceBytesSha256": sha256_digest(raw),
                }
            )
        artifacts.sort(
            key=lambda item: canonical_json_bytes(item["recordBinding"]["deviceUid"])
        )
        return artifacts

    def _envelope_metadata(
        self,
        *,
        subject_type: str,
        provider_key: tuple[str, int, str],
    ) -> dict:
        return {
            "subjectType": subject_type,
            "schemaVersion": 1,
            "collectionBarrierId": "capture-barrier-0001",
            "hostId": self.inventory.snapshot["hostId"],
            "kernelBootId": self.inventory.snapshot["kernelBootId"],
            "hostEpoch": self.inventory.snapshot["hostEpoch"],
            "agentIdentity": self.inventory.authority["agentIdentity"],
            "agentGeneration": self.inventory.snapshot["agentGeneration"],
            "providerId": provider_key[0],
            "providerVersion": provider_key[1],
            "providerDefinitionDigest": provider_key[2],
            "captureStartedAt": CAPTURE_STARTED_AT,
            "captureCompletedAt": CAPTURED_AT,
        }

    def _provider_captures(self) -> list[dict]:
        facts_by_provider: dict[
            tuple[str, int, str],
            dict[str, list[dict]],
        ] = {}
        records_by_uid = {item["deviceUid"]: item for item in self.inventory.records}
        for record in self.inventory.records:
            for fact in record["provenance"]["providerFacts"]:
                facts_by_provider.setdefault(
                    self._provider_key(fact),
                    {},
                ).setdefault(record["deviceUid"], []).append(copy.deepcopy(fact))

        captures: list[dict] = []
        for key in sorted(
            facts_by_provider,
            key=lambda item: canonical_json_bytes(list(item)),
        ):
            output = self._envelope_metadata(
                subject_type="PROVIDER_CAPTURE_OUTPUT_ENVELOPE",
                provider_key=key,
            )
            semantic = self._envelope_metadata(
                subject_type=("PROVIDER_CAPTURE_SEMANTIC_FACTS_ENVELOPE"),
                provider_key=key,
            )
            output_rows: list[dict] = []
            semantic_rows: list[dict] = []
            bindings: list[dict] = []
            for uid in sorted(
                facts_by_provider[key],
                key=canonical_json_bytes,
            ):
                record = records_by_uid[uid]
                facts = sorted(
                    facts_by_provider[key][uid],
                    key=lambda item: canonical_json_bytes(
                        [
                            item["factId"],
                            item["providerId"],
                            item["providerVersion"],
                            item["evidenceHash"],
                        ]
                    ),
                )
                pci_fact = self._pci_fact(record)
                is_pci = self._provider_key(pci_fact) == key
                if is_pci:
                    structure = copy.deepcopy(record["role"]["pciStructureFact"])
                    flr = copy.deepcopy(record["resetContract"]["pciFlrCapabilityFact"])
                    raw_pci = {
                        "providerFactId": pci_fact["factId"],
                        "observedAt": pci_fact["observedAt"],
                        "rawConfigSpaceHexOrNull": structure["rawConfigSpaceHexOrNull"],
                        "failureReasonCodeOrNull": structure["failureReasonCodeOrNull"],
                    }
                    bindings.append(
                        {
                            "deviceUid": uid,
                            "currentBdf": record["currentBdf"],
                            "providerFact": copy.deepcopy(pci_fact),
                            "pciStructureFact": structure,
                            "pciFlrCapabilityFact": flr,
                        }
                    )
                else:
                    structure = None
                    flr = None
                    raw_pci = None
                output_rows.append(
                    {
                        "deviceUid": uid,
                        "currentBdf": record["currentBdf"],
                        "providerFacts": copy.deepcopy(facts),
                        "pciConfigCaptureOrNull": raw_pci,
                    }
                )
                semantic_rows.append(
                    {
                        "deviceUid": uid,
                        "currentBdf": record["currentBdf"],
                        "providerFacts": copy.deepcopy(facts),
                        "pciStructureFactOrNull": structure,
                        "pciFlrCapabilityFactOrNull": flr,
                    }
                )
            output["deviceRows"] = output_rows
            semantic["deviceRows"] = semantic_rows
            output_raw = canonical_json_bytes(output)
            semantic_raw = canonical_json_bytes(semantic)
            capture = {
                "providerId": key[0],
                "providerVersion": key[1],
                "providerDefinitionDigest": key[2],
                "outputSchemaRef": (HOST_SNAPSHOT_PROVIDER_OUTPUT_SCHEMA_REF),
                "canonicalOutputBase64": base64.b64encode(output_raw).decode("ascii"),
                "outputBytesSha256": sha256_digest(output_raw),
                "semanticFactsSchemaRef": (
                    HOST_SNAPSHOT_PROVIDER_SEMANTIC_FACTS_SCHEMA_REF
                ),
                "semanticFactsBase64": base64.b64encode(semantic_raw).decode("ascii"),
                "semanticFactsDigest": sha256_digest(
                    PROVIDER_SEMANTIC_DOMAIN + semantic_raw
                ),
                "coveredDeviceUids": sorted(
                    facts_by_provider[key],
                    key=canonical_json_bytes,
                ),
                "deviceFactBindings": sorted(
                    bindings,
                    key=lambda item: canonical_json_bytes(
                        [
                            item["deviceUid"],
                            item["currentBdf"],
                            item["providerFact"]["factId"],
                        ]
                    ),
                ),
                "captureStartedAt": CAPTURE_STARTED_AT,
                "captureCompletedAt": CAPTURED_AT,
            }
            captures.append(capture)
        return captures

    def _capture_batch(self) -> dict:
        return {
            "subjectType": "HOST_INVENTORY_CAPTURE_BATCH",
            "schemaVersion": 1,
            "captureBatchId": "capture-batch-0001",
            "collectionBarrierId": "capture-barrier-0001",
            "scope": "FULL_HOST",
            "hostId": self.inventory.snapshot["hostId"],
            "kernelBootId": self.inventory.snapshot["kernelBootId"],
            "hostEpoch": self.inventory.snapshot["hostEpoch"],
            "agentIdentity": self.inventory.authority["agentIdentity"],
            "agentGeneration": self.inventory.snapshot["agentGeneration"],
            "captureStartedAt": CAPTURE_STARTED_AT,
            "captureCompletedAt": CAPTURED_AT,
            "providerCaptures": self._provider_captures(),
            "providerSemanticProjection": {},
            "topologyProjection": {},
            "noChangeProjection": {},
            "captureBatchDigest": None,
        }

    def rederive_projections(self) -> None:
        semantic_snapshot = {
            "hostId": self.batch["hostId"],
            "kernelBootId": self.batch["kernelBootId"],
            "hostEpoch": self.batch["hostEpoch"],
            "agentGeneration": self.batch["agentGeneration"],
            "policyHash": self.capability_policy.policy_hash,
            "snapshotFreshnessPolicyHash": self.freshness_policy["policyHash"],
        }
        semantics = derive_host_snapshot_semantics(
            semantic_snapshot,
            self.inventory.records,
        )
        self.batch["topologyProjection"] = thaw(semantics.topology_projection)
        self.batch["providerSemanticProjection"] = thaw(
            semantics.provider_semantic_projection
        )
        self.batch["noChangeProjection"] = derive_no_change_projection(
            snapshot=semantic_snapshot,
            agent_identity=self.batch["agentIdentity"],
            topology_digest=semantics.topology_digest,
            provider_facts_digest=semantics.provider_facts_digest,
        )

    def reseal_batch(self) -> None:
        for provider in self.batch["providerCaptures"]:
            output_raw = base64.b64decode(provider["canonicalOutputBase64"])
            semantic_raw = base64.b64decode(provider["semanticFactsBase64"])
            provider["outputBytesSha256"] = sha256_digest(output_raw)
            provider["semanticFactsDigest"] = sha256_digest(
                PROVIDER_SEMANTIC_DOMAIN + semantic_raw
            )
        self.batch["captureBatchDigest"] = None
        self.batch["captureBatchDigest"] = sha256_digest(
            CAPTURE_BATCH_DOMAIN + canonical_json_bytes(self.batch)
        )
        batch_raw = canonical_json_bytes(self.batch)
        self.capture_batch_artifact = {
            "schemaRef": (
                "contracts/directpath-host-snapshot-publication-trace."
                "schema.json#/$defs/captureBatch"
            ),
            "instance": copy.deepcopy(self.batch),
            "canonicalCaptureBatchBase64": base64.b64encode(batch_raw).decode("ascii"),
            "canonicalBytesSha256": sha256_digest(batch_raw),
        }

    def reseal_freshness_policy(
        self,
        *,
        rederive_batch: bool = True,
    ) -> None:
        self.freshness_policy["policyHash"] = None
        self.freshness_policy["policyHash"] = sha256_digest(
            FRESHNESS_POLICY_DOMAIN + canonical_json_bytes(self.freshness_policy)
        )
        raw = canonical_json_bytes(self.freshness_policy)
        self.freshness_policy_artifact = {
            "schemaRef": (
                "contracts/directpath-host-snapshot-publication-trace."
                "schema.json#/$defs/freshnessPolicy"
            ),
            "state": copy.deepcopy(self.freshness_policy),
            "canonicalInstanceBase64": base64.b64encode(raw).decode("ascii"),
            "instanceBytesSha256": sha256_digest(raw),
        }
        if rederive_batch and hasattr(self, "batch"):
            self.rederive_projections()
            self.reseal_batch()

    def set_provider_output(self, index: int, document: dict) -> None:
        self.batch["providerCaptures"][index]["canonicalOutputBase64"] = encode(
            document
        )

    def set_provider_semantic(self, index: int, document: dict) -> None:
        self.batch["providerCaptures"][index]["semanticFactsBase64"] = encode(document)

    def rebuild_capture_from_records(self) -> None:
        self.inventory.records.sort(
            key=lambda item: canonical_json_bytes(item["deviceUid"])
        )
        self.inventory.reseal()
        self.device_record_artifacts = self._device_artifacts()
        self.batch = self._capture_batch()
        self.rederive_projections()
        self.reseal_batch()

    def verify(
        self,
        *,
        capability_policy=None,
        limits: PublicationCaptureVerifierLimits | None = None,
        schemas: ContractSchemas | None = None,
    ):
        return verify_host_snapshot_capture_closure(
            schemas or self.schemas,
            capability_policy or self.capability_policy,
            capture_batch_artifact=canonical_json_bytes(self.capture_batch_artifact),
            freshness_policy_artifact=canonical_json_bytes(
                self.freshness_policy_artifact
            ),
            device_record_artifacts=tuple(
                canonical_json_bytes(item) for item in self.device_record_artifacts
            ),
            limits=limits,
        )


class PublicationCaptureVerificationTests(unittest.TestCase):
    def assert_rejected(
        self,
        fixture: PublicationFixture,
        code: str,
        *,
        capability_policy=None,
        limits=None,
    ) -> DirectPathVerificationError:
        with self.assertRaises(DirectPathVerificationError) as raised:
            fixture.verify(
                capability_policy=capability_policy,
                limits=limits,
            )
        self.assertEqual(code, raised.exception.code)
        return raised.exception

    def test_positive_capture_replays_exact_bytes_and_fixed_boundary(
        self,
    ) -> None:
        fixture = PublicationFixture()
        context = fixture.verify()

        self.assertEqual(
            HOST_SNAPSHOT_CAPTURE_AUTHORITY_BOUNDARY,
            context.authority_boundary,
        )
        self.assertFalse(context.product_authorized)
        self.assertEqual(
            "CALLER_STAMPED_CANDIDATE_REQUIRES_REPOSITORY_CAS",
            context.coordinate_authority_disposition,
        )
        self.assertEqual(
            "CALLER_SUPPLIED_CAPTURE_COMPLETION",
            context.freshness_time_basis,
        )
        self.assertEqual(
            HOST_SNAPSHOT_CAPTURE_PRODUCT_EVIDENCE_BLOCKERS,
            context.product_evidence_blockers,
        )
        self.assertEqual(1, len(context.provider_captures))
        self.assertEqual(
            context.capture_batch_digest,
            fixture.batch["captureBatchDigest"],
        )
        self.assertEqual(
            context.context_digest,
            context.verification_receipt["contextDigest"],
        )
        replayed = replay_host_snapshot_capture_closure(
            fixture.schemas,
            context,
        )
        self.assertEqual(context.context_digest, replayed.context_digest)
        with self.assertRaises(TypeError):
            context.capture_batch["hostId"] = "mutated"
        with self.assertRaises(TypeError):
            VerifiedHostSnapshotCaptureClosureContext()

    def test_two_device_provider_coverage_and_pci_bijection(self) -> None:
        fixture = PublicationFixture(two_devices=True)
        context = fixture.verify()

        self.assertEqual(2, len(context.candidate_device_records.device_records))
        self.assertEqual(
            2,
            len(context.provider_captures[0].pci_binding_device_uids),
        )

    def test_nonsemantic_raw_change_advances_evidence_not_no_change_hash(
        self,
    ) -> None:
        before = PublicationFixture()
        before_context = before.verify()
        after = PublicationFixture()
        record = after.inventory.records[0]
        raw = bytearray.fromhex(
            record["role"]["pciStructureFact"]["rawConfigSpaceHexOrNull"]
        )
        raw[0x80] ^= 0x5A
        after.inventory.bind_pci_capture(record, bytes(raw))
        after.rebuild_capture_from_records()
        after_context = after.verify()

        self.assertNotEqual(
            before_context.candidate_device_records.device_records[
                0
            ].device_record_hash,
            after_context.candidate_device_records.device_records[0].device_record_hash,
        )
        self.assertNotEqual(
            before_context.capture_batch_digest,
            after_context.capture_batch_digest,
        )
        self.assertEqual(
            before_context.no_change_projection["noChangeProjectionHash"],
            after_context.no_change_projection["noChangeProjectionHash"],
        )

    def test_multifunction_semantic_change_advances_no_change_hash(
        self,
    ) -> None:
        before = PublicationFixture()
        before_context = before.verify()
        after = PublicationFixture()
        record = after.inventory.records[0]
        raw = bytearray.fromhex(
            record["role"]["pciStructureFact"]["rawConfigSpaceHexOrNull"]
        )
        raw[0x0E] |= 0x80
        after.inventory.bind_pci_capture(record, bytes(raw))
        after.rebuild_capture_from_records()
        after_context = after.verify()

        self.assertTrue(
            after_context.snapshot_semantics.device_projections[0]["role"][
                "pciStructureFact"
            ]["multifunctionOrNull"]
        )
        self.assertNotEqual(
            before_context.no_change_projection["noChangeProjectionHash"],
            after_context.no_change_projection["noChangeProjectionHash"],
        )

    def test_provider_rows_require_executable_canonical_order(self) -> None:
        fixture = PublicationFixture(two_devices=True)
        output = decoded(fixture.batch["providerCaptures"][0]["canonicalOutputBase64"])
        output["deviceRows"].reverse()
        fixture.set_provider_output(0, output)
        fixture.reseal_batch()

        self.assert_rejected(
            fixture,
            "PUBLICATION_CAPTURE_NONCANONICAL_SET",
        )

    def test_device_artifacts_require_executable_canonical_order(self) -> None:
        fixture = PublicationFixture(two_devices=True)
        fixture.device_record_artifacts.reverse()

        self.assert_rejected(
            fixture,
            "PUBLICATION_CAPTURE_NONCANONICAL_SET",
        )

    def test_generic_provider_has_real_fact_rows_and_zero_pci_bindings(
        self,
    ) -> None:
        fixture = PublicationFixture(generic_provider=True)
        context = fixture.verify()

        self.assertEqual(2, len(context.provider_captures))
        generic = next(
            item
            for item in context.provider_captures
            if item.provider_id == "linux-owner-provider"
        )
        self.assertEqual((), generic.pci_binding_device_uids)
        self.assertTrue(generic.covered_device_uids)

    def test_unavailable_pci_capture_replays_closed_unknown_shape(self) -> None:
        fixture = PublicationFixture(unavailable_pci=True)
        context = fixture.verify()

        fact = context.provider_captures[0].semantic_facts_document["deviceRows"][0][
            "pciStructureFactOrNull"
        ]
        self.assertEqual("UNAVAILABLE", fact["captureStatus"])
        self.assertEqual("UNKNOWN", fact["headerLayout"])

    def test_raw_pci_tamper_is_rejected_after_all_outer_hashes_resealed(
        self,
    ) -> None:
        fixture = PublicationFixture()
        output = decoded(fixture.batch["providerCaptures"][0]["canonicalOutputBase64"])
        raw = bytearray.fromhex(
            output["deviceRows"][0]["pciConfigCaptureOrNull"]["rawConfigSpaceHexOrNull"]
        )
        raw[0x80] ^= 0x5A
        output["deviceRows"][0]["pciConfigCaptureOrNull"]["rawConfigSpaceHexOrNull"] = (
            raw.hex()
        )
        fixture.set_provider_output(0, output)
        fixture.reseal_batch()

        self.assert_rejected(
            fixture,
            "PUBLICATION_CAPTURE_PROVIDER_REPLAY_MISMATCH",
        )

    def test_semantic_pci_tamper_is_rejected_after_reseal(self) -> None:
        fixture = PublicationFixture()
        semantic = decoded(fixture.batch["providerCaptures"][0]["semanticFactsBase64"])
        substituted = digest("substituted-structure-fact")
        semantic["deviceRows"][0]["pciStructureFactOrNull"]["structureFactDigest"] = (
            substituted
        )
        semantic["deviceRows"][0]["pciFlrCapabilityFactOrNull"][
            "structureFactDigest"
        ] = substituted
        fixture.set_provider_semantic(0, semantic)
        fixture.reseal_batch()

        self.assert_rejected(
            fixture,
            "PUBLICATION_CAPTURE_PROVIDER_REPLAY_MISMATCH",
        )

    def test_generic_raw_semantic_fact_divergence_is_rejected(self) -> None:
        fixture = PublicationFixture(generic_provider=True)
        provider_index = next(
            index
            for index, item in enumerate(fixture.batch["providerCaptures"])
            if item["providerId"] == "linux-owner-provider"
        )
        semantic = decoded(
            fixture.batch["providerCaptures"][provider_index]["semanticFactsBase64"]
        )
        semantic["deviceRows"][0]["providerFacts"][0]["evidenceHash"] = digest(
            "substituted-generic-evidence"
        )
        fixture.set_provider_semantic(provider_index, semantic)
        fixture.reseal_batch()

        self.assert_rejected(
            fixture,
            "PUBLICATION_CAPTURE_PROVIDER_REPLAY_MISMATCH",
        )

    def test_unknown_coverage_uid_is_rejected(self) -> None:
        fixture = PublicationFixture()
        fixture.batch["providerCaptures"][0]["coveredDeviceUids"] = [
            "urn:qman:directpath:device:v1:unknown"
        ]
        fixture.reseal_batch()

        self.assert_rejected(
            fixture,
            "PUBLICATION_CAPTURE_PROVIDER_COVERAGE_MISMATCH",
        )

    def test_missing_pci_binding_is_rejected(self) -> None:
        fixture = PublicationFixture()
        fixture.batch["providerCaptures"][0]["deviceFactBindings"] = []
        fixture.reseal_batch()

        self.assert_rejected(
            fixture,
            "PUBLICATION_CAPTURE_PCI_BIJECTION_INVALID",
        )

    def test_provider_identity_substitution_is_rejected(self) -> None:
        fixture = PublicationFixture()
        provider = fixture.batch["providerCaptures"][0]
        provider["providerVersion"] = 2
        output = decoded(provider["canonicalOutputBase64"])
        semantic = decoded(provider["semanticFactsBase64"])
        output["providerVersion"] = 2
        semantic["providerVersion"] = 2
        fixture.set_provider_output(0, output)
        fixture.set_provider_semantic(0, semantic)
        fixture.reseal_batch()

        self.assert_rejected(
            fixture,
            "PUBLICATION_CAPTURE_PROVIDER_COVERAGE_MISMATCH",
        )

    def test_provider_interval_outside_batch_is_rejected(self) -> None:
        fixture = PublicationFixture()
        provider = fixture.batch["providerCaptures"][0]
        provider["captureStartedAt"] = "2026-07-24T01:59:28.999999Z"
        output = decoded(provider["canonicalOutputBase64"])
        semantic = decoded(provider["semanticFactsBase64"])
        output["captureStartedAt"] = provider["captureStartedAt"]
        semantic["captureStartedAt"] = provider["captureStartedAt"]
        fixture.set_provider_output(0, output)
        fixture.set_provider_semantic(0, semantic)
        fixture.reseal_batch()

        self.assert_rejected(
            fixture,
            "PUBLICATION_CAPTURE_INTERVAL_INVALID",
        )

    def test_record_capture_interval_must_exact_match_batch(self) -> None:
        fixture = PublicationFixture()
        record = copy.deepcopy(fixture.inventory.records[0])
        record["provenance"]["captureStartedAt"] = "2026-07-24T01:59:29.000001Z"
        record["provenance"]["providerFactsDigest"] = (
            derive_device_provider_facts_digest(record)
        )
        projection = copy.deepcopy(record)
        projection["deviceRecordHash"] = None
        record["deviceRecordHash"] = sha256_digest(canonical_json_bytes(projection))
        fixture.inventory.records[0] = record
        fixture.device_record_artifacts = fixture._device_artifacts()

        self.assert_rejected(
            fixture,
            "PUBLICATION_CAPTURE_INTERVAL_INVALID",
        )

    def test_stored_topology_projection_cannot_replace_record_replay(
        self,
    ) -> None:
        fixture = PublicationFixture()
        fixture.batch["topologyProjection"]["members"][0]["technicalTraits"] = [
            "PCI_EXPRESS_ENDPOINT",
            "SUBSTITUTED",
        ]
        fixture.reseal_batch()

        self.assert_rejected(
            fixture,
            "PUBLICATION_CAPTURE_DEVICE_PROJECTION_MISMATCH",
        )

    def test_independent_capability_policy_hash_is_required(self) -> None:
        fixture = PublicationFixture()
        second = verify_capability_policy(
            fixture.schemas,
            capability_policy_document(version=8),
            verified_at=VERIFY_AT,
        )

        self.assert_rejected(
            fixture,
            "PUBLICATION_CAPTURE_NO_CHANGE_PROJECTION_MISMATCH",
            capability_policy=second,
        )

    def test_missing_mandatory_fact_rejected_after_policy_reseal(
        self,
    ) -> None:
        fixture = PublicationFixture()
        fixture.freshness_policy["mandatoryProviderFacts"] = [
            {
                "providerId": "linux-pci-provider",
                "factId": "missing-mandatory-fact",
            }
        ]
        fixture.reseal_freshness_policy()

        self.assert_rejected(
            fixture,
            "PUBLICATION_CAPTURE_MANDATORY_FACT_MISSING",
        )

    def test_freshness_threshold_is_integer_microsecond_exact(self) -> None:
        accepted = PublicationFixture(
            pci_observed_at=CAPTURE_STARTED_AT,
            maximum_evidence_age_micros=1_000_000,
        )
        accepted.verify()

        stale = PublicationFixture(
            pci_observed_at=CAPTURE_STARTED_AT,
            maximum_evidence_age_micros=999_999,
        )
        self.assert_rejected(
            stale,
            "PUBLICATION_CAPTURE_MANDATORY_FACT_STALE",
        )

    def test_nonportable_provider_schema_ref_is_fail_closed(self) -> None:
        fixture = PublicationFixture()
        fixture.batch["providerCaptures"][0]["outputSchemaRef"] = (
            "contracts/directpath-portable-entities.schema.json#/$defs/providerFact"
        )
        fixture.reseal_batch()

        self.assert_rejected(
            fixture,
            "PUBLICATION_CAPTURE_PROVIDER_SCHEMA_UNSUPPORTED",
        )

    def test_all_zero_raw_config_is_not_present_device_evidence(self) -> None:
        fixture = PublicationFixture()
        output = decoded(fixture.batch["providerCaptures"][0]["canonicalOutputBase64"])
        output["deviceRows"][0]["pciConfigCaptureOrNull"]["rawConfigSpaceHexOrNull"] = (
            "00" * 256
        )
        fixture.set_provider_output(0, output)
        fixture.reseal_batch()

        self.assert_rejected(fixture, "PCI_CONFIG_CAPTURE_INVALID")

    def test_decoded_provider_budget_is_enforced_before_decode(self) -> None:
        fixture = PublicationFixture()
        limits = replace(
            DEFAULT_PUBLICATION_CAPTURE_LIMITS,
            max_decoded_provider_artifact_bytes=64,
        )

        self.assert_rejected(
            fixture,
            "PUBLICATION_CAPTURE_TOO_LARGE",
            limits=limits,
        )

    def test_receipt_binds_complete_algorithm_schema_identity(self) -> None:
        fixture = PublicationFixture()
        context = fixture.verify()

        identity = thaw(context.algorithm_identity)
        self.assertEqual(
            context.algorithm_identity_digest,
            identity["algorithmIdentityDigest"],
        )
        self.assertEqual(
            identity,
            thaw(context.verification_receipt["algorithmIdentity"]),
        )
        self.assertEqual(
            {
                "contracts/directpath-capability-policy.schema.json",
                "contracts/directpath-host-snapshot-publication-trace.schema.json",
                "contracts/directpath-identity-v1.schema.json",
                "contracts/directpath-portable-entities.schema.json",
                "contracts/directpath-portable-hash-subjects.schema.json",
            },
            {item["schemaRef"] for item in identity["schemaBindings"]},
        )
        for binding in identity["schemaBindings"]:
            self.assertEqual(
                fixture.schemas.digest_for_ref(
                    binding["schemaRef"],
                    path="test.captureAlgorithm.schemaBindings",
                ),
                binding["schemaDigest"],
            )

    def test_transitive_schema_change_advances_algorithm_and_context(self) -> None:
        fixture = PublicationFixture()
        official = fixture.verify()

        with tempfile.TemporaryDirectory() as temporary:
            modified_contracts = Path(temporary) / "contracts"
            shutil.copytree(CONTRACTS, modified_contracts)
            schema_path = (
                modified_contracts / "directpath-portable-entities.schema.json"
            )
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            schema["x-testSchemaIdentityNonce"] = "transitive-change"
            schema_path.write_text(
                json.dumps(schema, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            modified_schemas = ContractSchemas(modified_contracts)
            modified_policy = verify_capability_policy(
                modified_schemas,
                capability_policy_document(),
                verified_at=VERIFY_AT,
            )
            modified = fixture.verify(
                schemas=modified_schemas,
                capability_policy=modified_policy,
            )

        self.assertNotEqual(
            official.algorithm_identity_digest,
            modified.algorithm_identity_digest,
        )
        self.assertNotEqual(official.context_digest, modified.context_digest)

    def test_policy_verified_under_different_schema_identity_is_rejected(
        self,
    ) -> None:
        fixture = PublicationFixture()
        with tempfile.TemporaryDirectory() as temporary:
            modified_contracts = Path(temporary) / "contracts"
            shutil.copytree(CONTRACTS, modified_contracts)
            schema_path = modified_contracts / "directpath-capability-policy.schema.json"
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            schema["x-testSchemaIdentityNonce"] = "policy-schema-change"
            schema_path.write_text(
                json.dumps(schema, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            modified_schemas = ContractSchemas(modified_contracts)
            modified_policy = verify_capability_policy(
                modified_schemas,
                capability_policy_document(),
                verified_at=VERIFY_AT,
            )

        self.assert_rejected(
            fixture,
            "PUBLICATION_CAPTURE_POLICY_SCHEMA_MISMATCH",
            capability_policy=modified_policy,
        )

    def test_oversized_mapping_is_rejected_before_canonicalization(self) -> None:
        fixture = PublicationFixture()
        limits = replace(
            DEFAULT_PUBLICATION_CAPTURE_LIMITS,
            max_capture_artifact_bytes=1024,
        )
        oversized = {
            "oversizedMarker": "x" * 2048,
        }
        original = canonical_json_bytes

        def guarded_canonical_json_bytes(value):
            if isinstance(value, dict) and "oversizedMarker" in value:
                raise AssertionError("oversized mapping reached canonicalization")
            return original(value)

        with patch(
            "qman_directpath_core.publication_capture.canonical_json_bytes",
            side_effect=guarded_canonical_json_bytes,
        ):
            with self.assertRaises(DirectPathVerificationError) as raised:
                verify_host_snapshot_capture_closure(
                    fixture.schemas,
                    fixture.capability_policy,
                    capture_batch_artifact=oversized,
                    freshness_policy_artifact=canonical_json_bytes(
                        fixture.freshness_policy_artifact
                    ),
                    device_record_artifacts=tuple(
                        canonical_json_bytes(item)
                        for item in fixture.device_record_artifacts
                    ),
                    limits=limits,
                )
        self.assertEqual("PUBLICATION_CAPTURE_TOO_LARGE", raised.exception.code)

    def test_provider_count_limit_fails_before_capture_schema_walk(self) -> None:
        fixture = PublicationFixture(generic_provider=True)
        limits = replace(
            DEFAULT_PUBLICATION_CAPTURE_LIMITS,
            max_provider_captures=1,
        )
        with patch.object(
            fixture.schemas,
            "validate_ref",
            wraps=fixture.schemas.validate_ref,
        ) as validate_ref:
            self.assert_rejected(
                fixture,
                "PUBLICATION_CAPTURE_TOO_LARGE",
                limits=limits,
            )
        validated_refs = [call.args[0] for call in validate_ref.call_args_list]
        self.assertNotIn(
            HOST_SNAPSHOT_CAPTURE_BATCH_ARTIFACT_SCHEMA_REF,
            validated_refs,
        )

    def test_total_decoded_budget_is_reserved_before_base64_decode(self) -> None:
        fixture = PublicationFixture()
        limits = replace(
            DEFAULT_PUBLICATION_CAPTURE_LIMITS,
            max_total_decoded_bytes=1,
        )
        with patch(
            "qman_directpath_core.publication_capture.base64.b64decode",
            wraps=base64.b64decode,
        ) as decode_call:
            self.assert_rejected(
                fixture,
                "PUBLICATION_CAPTURE_TOO_LARGE",
                limits=limits,
            )
        decode_call.assert_not_called()

    def test_device_generation_must_be_committed_row_composable(self) -> None:
        fixture = PublicationFixture()
        fixture.inventory.records[0]["generations"]["deviceGeneration"] -= 1
        fixture.rebuild_capture_from_records()

        self.assert_rejected(
            fixture,
            "PUBLICATION_CAPTURE_COORDINATE_MISMATCH",
        )

    def test_candidate_records_must_share_one_resource_version(self) -> None:
        fixture = PublicationFixture(two_devices=True)
        fixture.inventory.records[1]["generations"]["resourceVersion"] += 1
        fixture.rebuild_capture_from_records()

        self.assert_rejected(
            fixture,
            "PUBLICATION_CAPTURE_COORDINATE_MISMATCH",
        )

    def test_raw_observed_at_substitution_is_rejected_after_reseal(self) -> None:
        fixture = PublicationFixture()
        output = decoded(fixture.batch["providerCaptures"][0]["canonicalOutputBase64"])
        output["deviceRows"][0]["pciConfigCaptureOrNull"]["observedAt"] = (
            "2026-07-24T01:59:29.500000Z"
        )
        fixture.set_provider_output(0, output)
        fixture.reseal_batch()

        self.assert_rejected(
            fixture,
            "PUBLICATION_CAPTURE_PROVIDER_REPLAY_MISMATCH",
        )

    def test_unavailable_failure_reason_substitution_is_rejected(self) -> None:
        fixture = PublicationFixture(unavailable_pci=True)
        output = decoded(fixture.batch["providerCaptures"][0]["canonicalOutputBase64"])
        output["deviceRows"][0]["pciConfigCaptureOrNull"][
            "failureReasonCodeOrNull"
        ] = "PCI_CONFIG_PERMISSION_DENIED"
        fixture.set_provider_output(0, output)
        fixture.reseal_batch()

        self.assert_rejected(
            fixture,
            "PUBLICATION_CAPTURE_PROVIDER_REPLAY_MISMATCH",
        )

    def test_callers_cannot_relax_portable_hard_limits(self) -> None:
        fixture = PublicationFixture()
        limits = PublicationCaptureVerifierLimits(
            max_json_depth=(DEFAULT_PUBLICATION_CAPTURE_LIMITS.max_json_depth + 1)
        )

        self.assert_rejected(
            fixture,
            "PUBLICATION_CAPTURE_LIMIT_INVALID",
            limits=limits,
        )


if __name__ == "__main__":
    unittest.main()
