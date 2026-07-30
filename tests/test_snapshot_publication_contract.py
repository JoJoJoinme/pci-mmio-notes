from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable
import unittest

from jsonschema import Draft202012Validator
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[1]
ZERO_DIGEST = "sha256:" + ("0" * 64)
ONE_DIGEST = "sha256:" + ("1" * 64)
TWO_DIGEST = "sha256:" + ("2" * 64)
SIGNATURE = "ed25519:" + ("A" * 86)
T0 = "2026-07-24T00:00:00.000000Z"
T1 = "2026-07-24T00:00:01.000000Z"
T2 = "2026-07-24T00:00:02.000000Z"


def load(relative_path: str) -> dict[str, Any]:
    value = json.loads((ROOT / relative_path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"{relative_path} must contain one JSON object")
    return value


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def bytes_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def domain_digest(domain: str, value: object) -> str:
    payload = domain.encode("ascii") + b"\x00" + canonical(value)
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def null_field_digest(domain: str, value: dict[str, Any], field: str) -> str:
    projection = copy.deepcopy(value)
    projection[field] = None
    return domain_digest(domain, projection)


def _walk_path(
    value: object,
    path: str,
    *,
    mutate_leaf: Any,
) -> int:
    parts = path.split(".")

    def visit(node: object, index: int) -> int:
        token = parts[index]
        is_array = token.endswith("[]")
        key = token[:-2] if is_array else token
        if not isinstance(node, dict) or key not in node:
            raise AssertionError(f"projection path does not resolve: {path}")
        target = node[key]
        if is_array:
            if not isinstance(target, list):
                raise AssertionError(f"projection path is not an array: {path}")
            if not target:
                raise AssertionError(f"projection path has no concrete leaf: {path}")
            if index == len(parts) - 1:
                for item_index, item in enumerate(target):
                    target[item_index] = mutate_leaf(item)
                return len(target)
            return sum(visit(item, index + 1) for item in target)
        if index == len(parts) - 1:
            node[key] = mutate_leaf(target)
            return 1
        return visit(target, index + 1)

    return visit(value, 0)


def _set_digest_null_paths(value: dict[str, Any], paths: list[str]) -> None:
    for path in paths:
        resolved = _walk_path(value, path, mutate_leaf=lambda _: None)
        if resolved < 1:
            raise AssertionError(f"projection path did not resolve: {path}")


def _mutate_path(value: dict[str, Any], path: str) -> None:
    def mutate_leaf(leaf: object) -> object:
        if leaf is None:
            return "tampered"
        if isinstance(leaf, bool):
            return not leaf
        if isinstance(leaf, int):
            return leaf + 1
        if isinstance(leaf, str):
            return leaf + "-tampered"
        raise AssertionError(f"unsupported projection leaf at {path}: {leaf!r}")

    _walk_path(value, path, mutate_leaf=mutate_leaf)


def _replace_at_path(
    value: dict[str, Any],
    path: tuple[str | int, ...],
    replacement: object,
) -> None:
    node: object = value
    for token in path[:-1]:
        if isinstance(token, int):
            if not isinstance(node, list):
                raise AssertionError(f"expected list while resolving {path}")
            node = node[token]
        else:
            if not isinstance(node, dict):
                raise AssertionError(f"expected object while resolving {path}")
            node = node[token]
    leaf = path[-1]
    if isinstance(leaf, int):
        if not isinstance(node, list):
            raise AssertionError(f"expected list leaf while resolving {path}")
        node[leaf] = replacement
    else:
        if not isinstance(node, dict):
            raise AssertionError(f"expected object leaf while resolving {path}")
        node[leaf] = replacement


def device_projection_digest(
    rule: dict[str, Any],
    value: dict[str, Any],
) -> str:
    projection = copy.deepcopy(value)
    projection[rule["digestField"]] = rule["digestFieldValueDuringHash"]
    _set_digest_null_paths(projection, rule["digestNullPaths"])
    return domain_digest(rule["digestDomain"], projection)


def topology_projection_digest(
    rule: dict[str, Any],
    value: dict[str, Any],
) -> str:
    projection = {
        field: copy.deepcopy(value[field])
        for field in rule["literalTopLevelFields"]
    }
    projection["members"] = [
        {
            field: copy.deepcopy(member[field])
            for field in rule["memberFields"]
        }
        for member in value["members"]
    ]
    projection[rule["digestField"]] = rule["digestFieldValueDuringHash"]
    return domain_digest(rule["digestDomain"], projection)


def recursive_refs(node: object) -> Iterable[str]:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                yield value
            yield from recursive_refs(value)
    elif isinstance(node, list):
        for value in node:
            yield from recursive_refs(value)


def registry_for_contracts() -> Registry:
    resources: list[tuple[str, Resource[Any]]] = []
    for path in sorted((ROOT / "contracts").glob("*.schema.json")):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(schema, dict) and isinstance(schema.get("$id"), str):
            resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def authority_validator(
    authority: dict[str, Any],
    definition: str,
) -> Draft202012Validator:
    return Draft202012Validator(
        {
            "$schema": authority["$schema"],
            "$defs": authority["$defs"],
            "$ref": f"#/$defs/{definition}",
        }
    )


def root_signature(key_id: str = "root-key-1") -> dict[str, Any]:
    return {
        "rootKeyId": key_id,
        "signedAt": T1,
        "algorithm": "Ed25519",
        "signature": SIGNATURE,
    }


def genesis_cas() -> dict[str, None]:
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


def prepared_anchor(
    *,
    anchor_version: int = 1,
    resource_version: int = 1,
    snapshot_epoch: int = 1,
    host_authority_version: int = 2,
    previous_digest: str | None = None,
) -> dict[str, Any]:
    if anchor_version == 1:
        cas: dict[str, Any] = genesis_cas()
    else:
        cas = {
            "expectedAnchorVersionOrNull": anchor_version - 1,
            "expectedResourceVersionOrNull": resource_version - 1,
            "expectedKernelBootIdOrNull": "boot-1",
            "expectedHostEpochOrNull": 1,
            "expectedAgentIdentityOrNull": "agent-1",
            "expectedAgentGenerationOrNull": 1,
            "expectedSnapshotEpochOrNull": snapshot_epoch - 1,
            "expectedSnapshotContentHashOrNull": ONE_DIGEST,
            "expectedHostAuthorityResourceVersionOrNull": (
                host_authority_version - 1
            ),
            "expectedAnchorDigestOrNull": previous_digest,
        }
    candidate = {
        "schemaVersion": 1,
        "recordType": "DIRECTPATH_HOST_SNAPSHOT_ROLLBACK_ANCHOR",
        "canonicalProfileId": "CANONICAL-JSON-V1",
        "recordState": "PREPARED",
        "hostId": "host-1",
        "kernelBootId": "boot-1",
        "hostEpoch": 1,
        "agentIdentity": "agent-1",
        "agentGeneration": 1,
        "acceptedSnapshotEpoch": snapshot_epoch,
        "acceptedSnapshotContentHash": TWO_DIGEST,
        "acceptedHostAuthorityResourceVersion": host_authority_version,
        "candidateProjectionDigest": ZERO_DIGEST,
        "anchorVersion": anchor_version,
        "resourceVersion": resource_version,
        "previousAnchorDigestOrNull": previous_digest,
        "updatedAt": T1,
        "authorityId": "external-host-snapshot-authority",
        "casPrecondition": cas,
        "prepareReceipt": {
            "schemaVersion": 1,
            "reservationId": f"reservation-{anchor_version}",
            "hostId": "host-1",
            "candidateProjectionDigest": ZERO_DIGEST,
            "predecessorAnchorDigestOrNull": previous_digest,
            "authorityId": "external-host-snapshot-authority",
            "preparedAt": T0,
            "expiresAt": T2,
            "retentionPolicy": "DURABLE_NON_REUSABLE_RECOVERY_TOMBSTONE",
            "rollbackAuthorityPreflightReceiptDigest": ZERO_DIGEST,
            "trustRootDigest": ONE_DIGEST,
            "receiptDigest": TWO_DIGEST,
            "rootSignatures": [root_signature()],
        },
        "anchorDigest": None,
        "receipt": None,
    }
    return candidate


def committed_anchor(prepared: dict[str, Any]) -> dict[str, Any]:
    committed = copy.deepcopy(prepared)
    committed["recordState"] = "COMMITTED"
    committed["anchorDigest"] = TWO_DIGEST
    committed["receipt"] = {
        "schemaVersion": 1,
        "receiptId": "anchor-receipt-1",
        "subjectAnchorDigest": TWO_DIGEST,
        "hostId": committed["hostId"],
        "kernelBootId": committed["kernelBootId"],
        "hostEpoch": committed["hostEpoch"],
        "agentIdentity": committed["agentIdentity"],
        "agentGeneration": committed["agentGeneration"],
        "acceptedSnapshotEpoch": committed["acceptedSnapshotEpoch"],
        "acceptedSnapshotContentHash": committed[
            "acceptedSnapshotContentHash"
        ],
        "acceptedHostAuthorityResourceVersion": committed[
            "acceptedHostAuthorityResourceVersion"
        ],
        "anchorVersion": committed["anchorVersion"],
        "resourceVersion": committed["resourceVersion"],
        "authorityId": committed["authorityId"],
        "issuedAt": T2,
        "trustRootDigest": ONE_DIGEST,
        "receiptDigest": ZERO_DIGEST,
        "rootSignatures": [root_signature()],
    }
    return committed


def choose_publication(
    current_projection: str | None,
    candidate_projection: str,
    *,
    current_freshness_policy_hash_or_null: str | None,
    active_freshness_policy_hash: str,
    evaluated_at_micros: int,
    current_captured_at_micros: int | None,
    oldest_evidence_at_micros: int | None,
    maximum_snapshot_age_micros: int,
    maximum_evidence_age_micros: int,
) -> tuple[str, bool, str]:
    if (
        current_captured_at_micros is not None
        and current_captured_at_micros > evaluated_at_micros
    ):
        raise ValueError("future freshness basis")
    if current_projection is None:
        return ("GENESIS_COMMITTED", False, "GENESIS_NO_CURRENT")
    if current_freshness_policy_hash_or_null != active_freshness_policy_hash:
        return (
            "SUCCESSOR_COMMITTED",
            False,
            "ACTIVE_POLICY_CHANGED_FORCES_SUCCESSOR",
        )
    if oldest_evidence_at_micros is None:
        raise ValueError("current policy mandatory evidence missing")
    if oldest_evidence_at_micros > evaluated_at_micros:
        raise ValueError("future freshness basis")
    refresh = (
        current_captured_at_micros is not None
        and evaluated_at_micros - current_captured_at_micros
        >= maximum_snapshot_age_micros
    ) or (
        oldest_evidence_at_micros is not None
        and evaluated_at_micros - oldest_evidence_at_micros
        >= maximum_evidence_age_micros
    )
    if current_projection != candidate_projection:
        return ("SUCCESSOR_COMMITTED", refresh, "CURRENT_POLICY_MATCHED")
    if refresh:
        return ("REFRESH_COMMITTED", True, "CURRENT_POLICY_MATCHED")
    return ("NO_CHANGE", False, "CURRENT_POLICY_MATCHED")


class SnapshotPublicationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.trace = load(
            "contracts/directpath-host-snapshot-publication-trace.schema.json"
        )
        cls.anchor = load(
            "contracts/directpath-host-snapshot-rollback-anchor.schema.json"
        )
        cls.freshness = load(
            "contracts/directpath-anchor-freshness-envelope.schema.json"
        )
        cls.authority = load(
            "contracts/directpath-authority-entities.schema.json"
        )
        cls.payload = load("contracts/directpath-operation-payload.schema.json")
        cls.envelope = load(
            "contracts/directpath-operation-envelope.schema.json"
        )
        cls.scenario_schema = load(
            "contracts/directpath-acceptance-scenario.schema.json"
        )
        cls.portable = load(
            "contracts/directpath-portable-control-contract.json"
        )
        cls.registry_c = load("acceptance/cases/registry-C.json")
        cls.registry = registry_for_contracts()

    def test_draft_2020_schemas_and_every_local_ref_resolve(self) -> None:
        selected = (
            self.trace,
            self.anchor,
            self.freshness,
            self.authority,
            self.payload,
            self.envelope,
            self.scenario_schema,
        )
        for schema in selected:
            with self.subTest(schema=schema["$id"]):
                Draft202012Validator.check_schema(schema)
                resolver = self.registry.resolver(schema["$id"])
                for ref in recursive_refs(schema):
                    resolver.lookup(ref)

    def test_capture_closure_profile_has_fixed_replay_and_no_authority_laundering(
        self,
    ) -> None:
        definitions = self.trace["$defs"]
        output = definitions["providerCaptureOutputEnvelope"]
        semantic = definitions["providerCaptureSemanticFactsEnvelope"]
        receipt = definitions["captureClosureVerificationReceipt"]

        self.assertEqual(
            "PROVIDER_CAPTURE_OUTPUT_ENVELOPE",
            output["properties"]["subjectType"]["const"],
        )
        self.assertEqual(
            "PROVIDER_CAPTURE_SEMANTIC_FACTS_ENVELOPE",
            semantic["properties"]["subjectType"]["const"],
        )
        self.assertIn(
            "pciConfigCaptureOrNull",
            definitions["providerCaptureOutputDeviceRow"]["required"],
        )
        self.assertEqual(
            "^[0-9a-f]{512}$",
            definitions["providerCaptureOutputPciConfig"]["properties"][
                "rawConfigSpaceHexOrNull"
            ]["oneOf"][1]["pattern"],
        )
        self.assertIn(
            "pciStructureFactOrNull",
            definitions["providerCaptureSemanticDeviceRow"]["required"],
        )
        self.assertIn(
            "pciFlrCapabilityFactOrNull",
            definitions["providerCaptureSemanticDeviceRow"]["required"],
        )
        self.assertEqual(
            "HOST_SNAPSHOT_CAPTURE_CLOSURE_VERIFIER_V2",
            receipt["properties"]["algorithmId"]["const"],
        )
        self.assertIn("algorithmIdentity", receipt["required"])
        self.assertEqual(
            "CALLER_STAMPED_CANDIDATE_REQUIRES_REPOSITORY_CAS",
            receipt["properties"]["coordinateAuthorityDisposition"]["const"],
        )
        self.assertEqual(
            "CALLER_SUPPLIED_CAPTURE_COMPLETION",
            receipt["properties"]["freshnessTimeBasis"]["const"],
        )
        self.assertEqual(
            "COMPONENT_CALLER_SUPPLIED_CAPTURE_BYTES_ONLY",
            receipt["properties"]["authorityBoundary"]["const"],
        )
        self.assertEqual(
            "COMPONENT_PREMISE_ONLY",
            receipt["properties"]["authorityDisposition"]["const"],
        )
        self.assertFalse(
            receipt["properties"]["productAuthorized"]["const"]
        )
        blockers = receipt["properties"]["productEvidenceBlockers"][
            "prefixItems"
        ]
        self.assertEqual(8, len(blockers))
        self.assertIn(
            "TARGET_COMMIT_PROVIDER_DECODER_BUILD_ATTESTATION_REQUIRED",
            {item["const"] for item in blockers},
        )
        self.assertIn(
            "CAPABILITY_POLICY_AUTHORITY_CAS_RECEIPT_REQUIRED",
            {item["const"] for item in blockers},
        )
        self.assertIn(
            "TRUSTED_PUBLICATION_EVALUATION_TIME_REQUIRED",
            {item["const"] for item in blockers},
        )
        self.assertIn(
            "portable component replay profile",
            " ".join(self.trace["x-qmanCaptureClosureRules"]),
        )

    def test_host_authority_has_one_durable_genesis_form(self) -> None:
        validator = authority_validator(
            self.authority,
            "ENTITY-HOST-AUTHORITY",
        )
        genesis = {
            "hostId": "host-1",
            "hostEpoch": 1,
            "kernelBootId": "boot-1",
            "agentIdentity": "agent-1",
            "agentGeneration": 1,
            "cooperationState": "RECONCILING",
            "lastSnapshotEpoch": 0,
            "currentSnapshotContentHash": None,
            "lastObservedAt": T0,
            "resourceVersion": 1,
        }
        validator.validate(genesis)
        for field, bad_value in (
            ("currentSnapshotContentHash", ZERO_DIGEST),
            ("cooperationState", "ONLINE_COOPERATIVE"),
        ):
            tampered = copy.deepcopy(genesis)
            tampered[field] = bad_value
            self.assertTrue(
                list(validator.iter_errors(tampered)),
                f"genesis tamper {field} was accepted",
            )
        successor = copy.deepcopy(genesis)
        successor.update(
            {
                "lastSnapshotEpoch": 1,
                "currentSnapshotContentHash": ZERO_DIGEST,
                "resourceVersion": 2,
            }
        )
        validator.validate(successor)
        rules = " ".join(
            self.authority["$defs"]["ENTITY-HOST-AUTHORITY"][
                "x-qmanCrossFieldRules"
            ]
        )
        self.assertIn("exact-preserves hostId", rules)
        self.assertIn("cannot claim owner/backend/lease/journal", rules)
        self.assertIn("lastObservedAt exact-equals", rules)

    def test_anchor_genesis_successor_and_host_freshness_profiles(self) -> None:
        anchor_validator = Draft202012Validator(
            self.anchor,
            registry=self.registry,
        )
        genesis_prepared = prepared_anchor()
        anchor_validator.validate(genesis_prepared)
        anchor_validator.validate(committed_anchor(genesis_prepared))

        successor_prepared = prepared_anchor(
            anchor_version=2,
            resource_version=2,
            snapshot_epoch=2,
            host_authority_version=3,
            previous_digest=TWO_DIGEST,
        )
        anchor_validator.validate(successor_prepared)
        anchor_validator.validate(committed_anchor(successor_prepared))

        invalid = copy.deepcopy(genesis_prepared)
        invalid["anchorDigest"] = ZERO_DIGEST
        self.assertTrue(list(anchor_validator.iter_errors(invalid)))
        invalid = committed_anchor(genesis_prepared)
        invalid["receipt"] = None
        self.assertTrue(list(anchor_validator.iter_errors(invalid)))
        invalid = copy.deepcopy(genesis_prepared)
        invalid["previousAnchorDigestOrNull"] = ONE_DIGEST
        self.assertTrue(list(anchor_validator.iter_errors(invalid)))

        freshness = {
            "schemaVersion": 1,
            "envelopeId": "freshness-1",
            "anchorKind": "HOST_SNAPSHOT",
            "authorityId": "external-host-snapshot-authority",
            "subjectId": "host-1",
            "anchorPath": "hosts/host-1/current",
            "anchorBlobSha256": ZERO_DIGEST,
            "anchorSchemaRef": (
                "contracts/directpath-host-snapshot-rollback-anchor.schema.json"
            ),
            "anchorSchemaSha256": ONE_DIGEST,
            "anchorDigest": TWO_DIGEST,
            "anchorVersion": 1,
            "resourceVersion": 1,
            "observedAt": T0,
            "expiresAt": T2,
            "verifierNonce": "A" * 22,
            "trustRootDigest": ONE_DIGEST,
            "freshnessReceiptDigest": ZERO_DIGEST,
            "rootSignatures": [root_signature()],
        }
        Draft202012Validator(
            self.freshness,
            registry=self.registry,
        ).validate(freshness)
        freshness["anchorSchemaRef"] = (
            "contracts/directpath-catalog-rollback-anchor.schema.json"
        )
        self.assertTrue(
            list(
                Draft202012Validator(
                    self.freshness,
                    registry=self.registry,
                ).iter_errors(freshness)
            )
        )

    def test_refresh_successor_and_no_change_are_mutually_exclusive(self) -> None:
        common = {
            "current_freshness_policy_hash_or_null": "policy-v1",
            "active_freshness_policy_hash": "policy-v1",
            "evaluated_at_micros": 10_000_000,
            "current_captured_at_micros": 9_000_001,
            "oldest_evidence_at_micros": 9_000_001,
            "maximum_snapshot_age_micros": 1_000_000,
            "maximum_evidence_age_micros": 1_000_000,
        }
        self.assertEqual(
            ("NO_CHANGE", False, "CURRENT_POLICY_MATCHED"),
            choose_publication("same", "same", **common),
        )
        at_threshold = dict(common)
        at_threshold["current_captured_at_micros"] = 9_000_000
        self.assertEqual(
            ("REFRESH_COMMITTED", True, "CURRENT_POLICY_MATCHED"),
            choose_publication("same", "same", **at_threshold),
        )
        self.assertEqual(
            ("SUCCESSOR_COMMITTED", True, "CURRENT_POLICY_MATCHED"),
            choose_publication("old", "new", **at_threshold),
        )
        self.assertEqual(
            ("GENESIS_COMMITTED", False, "GENESIS_NO_CURRENT"),
            choose_publication(
                None,
                "new",
                current_freshness_policy_hash_or_null=None,
                active_freshness_policy_hash="policy-v1",
                evaluated_at_micros=10,
                current_captured_at_micros=None,
                oldest_evidence_at_micros=None,
                maximum_snapshot_age_micros=1,
                maximum_evidence_age_micros=1,
            ),
        )
        future = dict(common)
        future["oldest_evidence_at_micros"] = 10_000_001
        with self.assertRaisesRegex(ValueError, "future"):
            choose_publication("same", "same", **future)

        switched_policy = dict(common)
        switched_policy["active_freshness_policy_hash"] = "policy-v2"
        switched_policy["oldest_evidence_at_micros"] = None
        self.assertEqual(
            (
                "SUCCESSOR_COMMITTED",
                False,
                "ACTIVE_POLICY_CHANGED_FORCES_SUCCESSOR",
            ),
            choose_publication("old-policy-projection", "new", **switched_policy),
        )
        missing_same_policy = dict(common)
        missing_same_policy["oldest_evidence_at_micros"] = None
        with self.assertRaisesRegex(ValueError, "mandatory evidence missing"):
            choose_publication("same", "same", **missing_same_policy)

        decision = self.trace["$defs"]["freshnessDecision"]
        self.assertIn("evaluationDisposition", decision["required"])
        self.assertEqual(
            {
                "GENESIS_NO_CURRENT",
                "CURRENT_POLICY_MATCHED",
                "ACTIVE_POLICY_CHANGED_FORCES_SUCCESSOR",
            },
            set(decision["properties"]["evaluationDisposition"]["enum"]),
        )
        rules = " ".join(self.trace["x-qmanPublicationRules"])
        for token in (
            "Equality at the threshold requires refresh",
            "SUCCESSOR_COMMITTED requires",
            "REFRESH_COMMITTED requires",
            "NO_CHANGE requires",
            "ACTIVE_POLICY_CHANGED_FORCES_SUCCESSOR",
            "candidate capture closure, not predecessor records",
        ):
            self.assertIn(token, rules)

    def test_device_projection_is_closed_and_every_category_is_hashed(self) -> None:
        projection_schema = self.trace["$defs"]["deviceSemanticProjection"]
        projection = projection_schema["x-qmanProjectionFromDeviceRecord"]
        portable_entities = load(
            "contracts/directpath-portable-entities.schema.json"
        )
        source = portable_entities["$defs"]["ENTITY-DEVICE-RECORD"]
        self.assertEqual(3, source["properties"]["schemaVersion"]["const"])
        self.assertIn(
            "pciStructureFact",
            portable_entities["$defs"]["deviceRole"]["required"],
        )
        self.assertIn(
            "pciFlrCapabilityFact",
            portable_entities["$defs"]["resetContract"]["required"],
        )
        self.assertEqual(
            {
                "subjectType": "DEVICE_TOPOLOGY_SEMANTIC_PROJECTION",
                "schemaVersion": 2,
            },
            projection["literalFields"],
        )
        source_semantic_fields = set(source["required"]) - {
            "subjectType",
            "schemaVersion",
            "generations",
            "deviceRecordHash",
        }
        projected_source_fields = set(projection["exactCopyFields"]) | {
            "health",
            "provenance",
        }
        self.assertEqual(source_semantic_fields, projected_source_fields)
        self.assertEqual(
            "QMAN-DIRECTPATH/DEVICE-TOPOLOGY-SEMANTIC-PROJECTION/V2",
            projection["digestDomain"],
        )

        digest_null_paths = set(projection["digestNullPaths"])
        self.assertTrue(
            {
                "role.pciStructureFact.providerFactId",
                "role.pciStructureFact.rawConfigSpaceHexOrNull",
                "role.pciStructureFact.rawConfigSpaceSha256OrNull",
                "role.pciStructureFact.captureEvidenceDigest",
                "role.pciStructureFact.rawHeaderTypeByteOrNull",
                "role.pciStructureFact.pcieCapabilityOffsetOrNull",
                "role.pciStructureFact.rawPcieCapabilitiesRegisterOrNull",
                "role.pciStructureFact.structureFactDigest",
                "resetContract.resetProviderFactId",
                "resetContract.pciFlrCapabilityFact.structureFactDigest",
                (
                    "resetContract.pciFlrCapabilityFact"
                    ".pcieCapabilityOffsetOrNull"
                ),
                (
                    "resetContract.pciFlrCapabilityFact"
                    ".deviceCapabilitiesDwordOrNull"
                ),
                "resetContract.pciFlrCapabilityFact.flrFactDigest",
            }.issubset(digest_null_paths)
        )
        for semantic_path in (
            "role.pciStructureFact.vendorIdOrNull",
            "role.pciStructureFact.headerLayout",
            "role.pciStructureFact.multifunctionOrNull",
            "role.pciStructureFact.pcieCapabilityState",
            "role.pciStructureFact.pcieCapabilityVersionOrNull",
            "role.pciStructureFact.pcieDevicePortTypeOrNull",
            "resetContract.pciFlrCapabilityFact.state",
            (
                "resetContract.pciFlrCapabilityFact"
                ".functionLevelResetCapableOrNull"
            ),
        ):
            self.assertNotIn(semantic_path, digest_null_paths)

        structure_fact = {
            "state": "KNOWN",
            "captureStatus": "COMPLETE",
            "providerFactId": "pci-config-fact-1",
            "rawConfigSpaceHexOrNull": "00" * 256,
            "rawConfigSpaceSha256OrNull": ZERO_DIGEST,
            "failureReasonCodeOrNull": None,
            "captureEvidenceDigest": TWO_DIGEST,
            "vendorIdOrNull": "1000",
            "deviceIdOrNull": "00c9",
            "revisionIdOrNull": "01",
            "classCodeOrNull": "010700",
            "subsystemVendorIdOrNull": "1028",
            "subsystemDeviceIdOrNull": "1f4a",
            "rawHeaderTypeByteOrNull": 0,
            "headerLayout": "TYPE_0",
            "multifunctionOrNull": False,
            "subordinateBusNumberOrNull": None,
            "subordinateBusPresentOrNull": False,
            "pcieCapabilityState": "PRESENT",
            "pcieCapabilityOffsetOrNull": 64,
            "pcieCapabilityVersionOrNull": 2,
            "pcieDevicePortTypeOrNull": "ENDPOINT",
            "rawPcieCapabilitiesRegisterOrNull": 2,
            "structureFactDigest": ZERO_DIGEST,
            "authorityBoundary": (
                "COMPONENT_CALLER_SUPPLIED_RAW_CONFIG_BYTES_ONLY"
            ),
            "productAuthorized": False,
        }
        flr_fact = {
            "state": "PRESENT",
            "structureFactDigest": ZERO_DIGEST,
            "pcieCapabilityOffsetOrNull": 64,
            "deviceCapabilitiesDwordOrNull": 1 << 28,
            "functionLevelResetCapableOrNull": True,
            "flrFactDigest": ONE_DIGEST,
        }
        provider_fact = {
            "factId": "pci-config-fact-1",
            "providerId": "pci-config-provider",
            "providerVersion": 1,
            "providerDefinitionDigest": ONE_DIGEST,
            "observedAt": T1,
            "evidenceHash": TWO_DIGEST,
        }
        provider_capture = {
            "providerId": "pci-config-provider",
            "providerVersion": 1,
            "providerDefinitionDigest": ONE_DIGEST,
            "outputSchemaRef": (
                "contracts/directpath-portable-entities.schema.json"
            ),
            "canonicalOutputBase64": "e30=",
            "outputBytesSha256": ZERO_DIGEST,
            "semanticFactsSchemaRef": (
                "contracts/directpath-portable-entities.schema.json"
            ),
            "semanticFactsBase64": "e30=",
            "semanticFactsDigest": ONE_DIGEST,
            "coveredDeviceUids": ["device-1"],
            "deviceFactBindings": [
                {
                    "deviceUid": "device-1",
                    "currentBdf": "0000:01:00.0",
                    "providerFact": provider_fact,
                    "pciStructureFact": structure_fact,
                    "pciFlrCapabilityFact": flr_fact,
                }
            ],
            "captureStartedAt": T0,
            "captureCompletedAt": T2,
        }
        self.assertIn(
            "deviceFactBindings",
            self.trace["$defs"]["providerCapture"]["required"],
        )
        self.assertEqual(
            {
                "deviceUid",
                "currentBdf",
                "providerFact",
                "pciStructureFact",
                "pciFlrCapabilityFact",
            },
            set(self.trace["$defs"]["deviceFactBinding"]["required"]),
        )
        provider_capture_validator = Draft202012Validator(
            {
                "$schema": self.trace["$schema"],
                "$id": self.trace["$id"],
                "$defs": self.trace["$defs"],
                "$ref": "#/$defs/providerCapture",
            },
            registry=self.registry,
        )
        provider_capture_validator.validate(provider_capture)
        generic_capture = copy.deepcopy(provider_capture)
        generic_capture["deviceFactBindings"] = []
        provider_capture_validator.validate(generic_capture)
        zero_coverage_capture = copy.deepcopy(generic_capture)
        zero_coverage_capture["coveredDeviceUids"] = []
        self.assertFalse(
            provider_capture_validator.is_valid(zero_coverage_capture)
        )

        provider_projection_validator = Draft202012Validator(
            {
                "$schema": self.trace["$schema"],
                "$id": self.trace["$id"],
                "$defs": self.trace["$defs"],
                "$ref": "#/$defs/providerSemanticProjection",
            },
            registry=self.registry,
        )
        provider_projection = {
            "subjectType": "HOST_PROVIDER_SEMANTIC_PROJECTION",
            "schemaVersion": 1,
            "providers": [
                {
                    "providerId": provider_capture["providerId"],
                    "providerVersion": provider_capture["providerVersion"],
                    "providerDefinitionDigest": provider_capture[
                        "providerDefinitionDigest"
                    ],
                    "coveredDeviceUids": ["device-1"],
                }
            ],
            "providerFactsDigest": ZERO_DIGEST,
        }
        provider_projection_validator.validate(provider_projection)
        provider_projection["providers"][0]["coveredDeviceUids"] = []
        self.assertFalse(
            provider_projection_validator.is_valid(provider_projection)
        )

        member: dict[str, Any] = {
            "subjectType": "DEVICE_TOPOLOGY_SEMANTIC_PROJECTION",
            "schemaVersion": 2,
            "hostId": "host-1",
            "deviceUid": "device-1",
            "immutableIdentity": {"identity": "slot-a"},
            "identityFingerprint": ZERO_DIGEST,
            "currentBdf": "0000:01:00.0",
            "physicalPathProvider": {"provider": "ACPI"},
            "physicalPath": {"path": "ACPI0001"},
            "role": {
                "structuralRole": "ENDPOINT_PAYLOAD",
                "functionRole": "STORAGE",
                "pciStructureFact": copy.deepcopy(structure_fact),
                "roleFactsDigest": ZERO_DIGEST,
                "provenanceDigest": ONE_DIGEST,
            },
            "iommuProvider": {
                "mode": "IOMMU",
                "evidenceHash": ZERO_DIGEST,
            },
            "physicalIsolationDomain": {
                "state": "KNOWN",
                "provenanceDigest": ZERO_DIGEST,
            },
            "dependencyDomains": [
                {
                    "kind": "FUNCTIONAL",
                    "state": "KNOWN",
                    "provenanceDigest": ZERO_DIGEST,
                    "edges": [
                        {
                            "targetDeviceUid": "device-1",
                            "provenanceDigest": ONE_DIGEST,
                        }
                    ],
                }
            ],
            "dependencyActions": [
                {
                    "deviceUid": "device-1",
                    "action": "INCLUDE",
                    "provenanceDigest": ZERO_DIGEST,
                }
            ],
            "resetContract": {
                "selectedMethodOrNull": "PCI_FLR",
                "contractDigest": ZERO_DIGEST,
                "provenanceDigest": ONE_DIGEST,
                "resetProviderFactId": "pci-reset-fact-1",
                "pciFlrCapabilityFact": copy.deepcopy(flr_fact),
            },
            "owner": {
                "state": "UNOWNED",
                "provenanceDigest": ZERO_DIGEST,
            },
            "bars": [
                {
                    "barKind": "MEMORY",
                    "index": 0,
                    "sizeBytes": 4096,
                    "provenanceDigest": ZERO_DIGEST,
                }
            ],
            "interrupts": {
                "mode": "MSI_X",
                "provenanceDigest": ZERO_DIGEST,
            },
            "technicalTraits": ["PCIE"],
            "health": {
                "state": "HEALTHY",
                "lastResetResult": "PASS",
                "quarantineReasonCodeOrNull": None,
                "healthEvidenceHash": ZERO_DIGEST,
            },
            "provenance": {
                "providerFacts": [
                    {
                        "factId": "pci-config-fact-1",
                        "providerId": "pci-config-provider",
                        "providerVersion": 1,
                        "providerDefinitionDigest": ONE_DIGEST,
                        "evidenceHash": TWO_DIGEST,
                    }
                ],
                "providerFactsDigest": ZERO_DIGEST,
            },
            "deviceSemanticDigest": ZERO_DIGEST,
        }

        binding = provider_capture["deviceFactBindings"][0]
        self.assertEqual(member["deviceUid"], binding["deviceUid"])
        self.assertEqual(member["currentBdf"], binding["currentBdf"])
        self.assertEqual(
            member["role"]["pciStructureFact"],
            binding["pciStructureFact"],
        )
        self.assertEqual(
            member["resetContract"]["pciFlrCapabilityFact"],
            binding["pciFlrCapabilityFact"],
        )
        normalized_provider_fact = member["provenance"]["providerFacts"][0]
        self.assertEqual(
            normalized_provider_fact,
            {
                field: provider_fact[field]
                for field in projection["normalizedFields"]["provenance"][
                    "providerFactExactCopyFields"
                ]
            },
        )
        capture_closure_rules = " ".join(
            self.trace["x-qmanCaptureClosureRules"]
        )
        self.assertIn("exact bijection", capture_closure_rules)
        self.assertIn("DeviceRecord V3", capture_closure_rules)
        self.assertIn("deviceFactBindings", capture_closure_rules)

        base_device_hash = device_projection_digest(projection, member)
        member["deviceSemanticDigest"] = base_device_hash
        topology_rule = self.trace["$defs"]["topologyProjection"][
            "x-qmanDigestProjection"
        ]
        self.assertEqual(
            ["deviceUid", "deviceSemanticDigest"],
            topology_rule["memberFields"],
        )
        self.assertEqual(
            "QMAN-DIRECTPATH/HOST-TOPOLOGY-PROJECTION/V2",
            topology_rule["digestDomain"],
        )
        topology = {
            "subjectType": "HOST_TOPOLOGY_SEMANTIC_PROJECTION",
            "schemaVersion": 2,
            "hostId": "host-1",
            "kernelBootId": "boot-1",
            "hostEpoch": 1,
            "agentGeneration": 1,
            "members": [copy.deepcopy(member)],
            "topologyDigest": ZERO_DIGEST,
        }
        base_topology_hash = topology_projection_digest(topology_rule, topology)
        topology["topologyDigest"] = base_topology_hash
        provider_hash = ONE_DIGEST
        no_change_rule = self.trace["$defs"]["noChangeProjection"][
            "x-qmanDigestProjection"
        ]
        self.assertEqual(
            "QMAN-DIRECTPATH/HOST-SNAPSHOT-NO-CHANGE/V2",
            no_change_rule["digestDomain"],
        )
        no_change = {
            "subjectType": "HOST_SNAPSHOT_NO_CHANGE_PROJECTION",
            "schemaVersion": 2,
            "hostId": "host-1",
            "kernelBootId": "boot-1",
            "hostEpoch": 1,
            "agentIdentity": "agent-1",
            "agentGeneration": 1,
            "topologyDigest": base_topology_hash,
            "providerFactsDigest": provider_hash,
            "policyHash": TWO_DIGEST,
            "snapshotFreshnessPolicyHash": ZERO_DIGEST,
            "noChangeProjectionHash": ZERO_DIGEST,
        }
        base_no_change_hash = null_field_digest(
            no_change_rule["digestDomain"],
            no_change,
            no_change_rule["digestField"],
        )

        field_mutations: dict[str, tuple[tuple[str | int, ...], object]] = {
            "hostId": (("hostId",), "host-2"),
            "deviceUid": (("deviceUid",), "device-2"),
            "immutableIdentity": (
                ("immutableIdentity", "identity"),
                "slot-b",
            ),
            "identityFingerprint": (
                ("identityFingerprint",),
                TWO_DIGEST,
            ),
            "currentBdf": (("currentBdf",), "0000:01:00.1"),
            "physicalPathProvider": (
                ("physicalPathProvider", "provider"),
                "SMBIOS",
            ),
            "physicalPath": (("physicalPath", "path"), "ACPI0002"),
            "role": (("role", "structuralRole"), "FABRIC_DEPENDENCY"),
            "iommuProvider": (("iommuProvider", "mode"), "NO_IOMMU"),
            "physicalIsolationDomain": (
                ("physicalIsolationDomain", "state"),
                "UNKNOWN",
            ),
            "dependencyDomains": (
                ("dependencyDomains", 0, "state"),
                "UNKNOWN",
            ),
            "dependencyActions": (
                ("dependencyActions", 0, "action"),
                "DENY",
            ),
            "resetContract": (
                ("resetContract", "selectedMethodOrNull"),
                "BUS_RESET",
            ),
            "owner": (("owner", "state"), "HOST_OWNED"),
            "bars": (("bars", 0, "sizeBytes"), 8192),
            "interrupts": (("interrupts", "mode"), "MSI"),
            "technicalTraits": (("technicalTraits", 0), "PCIE_GEN4"),
            "health": (("health", "state"), "DEGRADED"),
            "provenance": (
                ("provenance", "providerFacts", 0, "providerId"),
                "pci-config-provider-v2",
            ),
        }
        self.assertEqual(
            set(projection["exactCopyFields"]) | {"health", "provenance"},
            set(field_mutations),
        )
        for field, (path, replacement) in field_mutations.items():
            with self.subTest(field=field):
                tampered = copy.deepcopy(member)
                _replace_at_path(tampered, path, replacement)
                changed_device_hash = device_projection_digest(
                    projection,
                    tampered,
                )
                self.assertNotEqual(base_device_hash, changed_device_hash)
                changed_topology = copy.deepcopy(topology)
                tampered["deviceSemanticDigest"] = changed_device_hash
                changed_topology["members"][0] = tampered
                changed_topology_hash = topology_projection_digest(
                    topology_rule,
                    changed_topology,
                )
                self.assertNotEqual(base_topology_hash, changed_topology_hash)
                changed_no_change = copy.deepcopy(no_change)
                changed_no_change["topologyDigest"] = changed_topology_hash
                self.assertNotEqual(
                    base_no_change_hash,
                    null_field_digest(
                        no_change_rule["digestDomain"],
                        changed_no_change,
                        no_change_rule["digestField"],
                    ),
                )
                self.assertEqual(provider_hash, no_change["providerFactsDigest"])

        for path in projection["digestNullPaths"]:
            with self.subTest(evidence_only_path=path):
                tampered = copy.deepcopy(member)
                _mutate_path(tampered, path)
                self.assertEqual(
                    base_device_hash,
                    device_projection_digest(projection, tampered),
                )

        semantic_pci_mutations = {
            "role.pciStructureFact.vendorIdOrNull": "1001",
            "role.pciStructureFact.headerLayout": "TYPE_1",
            "role.pciStructureFact.multifunctionOrNull": True,
            "role.pciStructureFact.pcieCapabilityState": "ABSENT",
            "role.pciStructureFact.pcieCapabilityVersionOrNull": 3,
            (
                "role.pciStructureFact.pcieDevicePortTypeOrNull"
            ): "LEGACY_ENDPOINT",
            "resetContract.pciFlrCapabilityFact.state": "ABSENT",
            (
                "resetContract.pciFlrCapabilityFact"
                ".functionLevelResetCapableOrNull"
            ): False,
        }
        for path, replacement in semantic_pci_mutations.items():
            with self.subTest(pci_semantic_path=path):
                tampered = copy.deepcopy(member)
                _replace_at_path(
                    tampered,
                    tuple(path.split(".")),
                    replacement,
                )
                changed_device_hash = device_projection_digest(
                    projection,
                    tampered,
                )
                self.assertNotEqual(base_device_hash, changed_device_hash)
                tampered["deviceSemanticDigest"] = changed_device_hash
                changed_topology = copy.deepcopy(topology)
                changed_topology["members"][0] = tampered
                changed_topology_hash = topology_projection_digest(
                    topology_rule,
                    changed_topology,
                )
                self.assertNotEqual(base_topology_hash, changed_topology_hash)
                changed_no_change = copy.deepcopy(no_change)
                changed_no_change["topologyDigest"] = changed_topology_hash
                self.assertNotEqual(
                    base_no_change_hash,
                    null_field_digest(
                        no_change_rule["digestDomain"],
                        changed_no_change,
                        no_change_rule["digestField"],
                    ),
                )

        topology_evidence_only = copy.deepcopy(topology)
        topology_evidence_only["members"][0]["health"][
            "healthEvidenceHash"
        ] = TWO_DIGEST
        self.assertEqual(
            base_topology_hash,
            topology_projection_digest(
                topology_rule,
                topology_evidence_only,
            ),
            "topology digest must shrink each stored member to UID + semantic digest",
        )

    def test_mutation_audit_outbox_commit_and_trace_hashes_are_acyclic(self) -> None:
        availability = {
            "availabilityAuthorityId": "availability-1",
            "clusterId": "cluster-1",
            "authorityScope": "GLOBAL_DIRECTPATH_AVAILABILITY",
            "lastMutationDigest": ZERO_DIGEST,
            "lastMutatedAt": T1,
            "resourceVersion": 2,
        }
        audit = {
            "schemaVersion": 1,
            "auditEventId": "audit-1",
            "operationId": "OP-CAPTURE-HOST-SNAPSHOT",
            "commandId": "command-1",
            "transactionId": "transaction-1",
            "commitId": "commit-1",
            "targetRepositoryObjectFormat": "SHA256",
            "targetRepositoryCommit": "a" * 64,
            "hostId": "host-1",
            "anchorReservationId": "reservation-1",
            "anchorPrepareReceiptDigest": ONE_DIGEST,
            "anchorCandidateProjectionDigest": TWO_DIGEST,
            "requiredAnchorVersion": 1,
            "snapshotContentHash": ONE_DIGEST,
            "hostAuthorityResourceVersion": 2,
            "availabilityAuthorityResourceVersion": 2,
            "mutationSetHash": ZERO_DIGEST,
            "priorAuditDigestOrNull": None,
            "createdAt": T1,
            "auditDigest": ZERO_DIGEST,
        }
        outbox = {
            "schemaVersion": 1,
            "outboxEventId": "outbox-1",
            "eventType": "HOST_SNAPSHOT_PUBLICATION_COMMITTED_PENDING_ANCHOR",
            "aggregateId": "host-1",
            "transactionId": "transaction-1",
            "commitId": "commit-1",
            "anchorReservationId": "reservation-1",
            "anchorPrepareReceiptDigest": ONE_DIGEST,
            "anchorCandidateProjectionDigest": TWO_DIGEST,
            "requiredAnchorVersion": 1,
            "deliveryGate": "REQUIRE_LIVE_COMMITTED_ANCHOR_AND_FRESH_NONCE",
            "deliveryAttemptCountBeforeAnchor": 0,
            "deliverySuccessCountBeforeAnchor": 0,
            "snapshotContentHash": ONE_DIGEST,
            "hostAuthorityResourceVersion": 2,
            "availabilityAuthorityResourceVersion": 2,
            "mutationSetHash": ZERO_DIGEST,
            "payloadHash": ZERO_DIGEST,
            "createdAt": T1,
            "resourceVersion": 1,
            "outboxDigest": ZERO_DIGEST,
        }
        outbox["payloadHash"] = domain_digest(
            "QMAN-DIRECTPATH/HOST-SNAPSHOT-PUBLISHED-PAYLOAD/V1",
            {
                key: outbox[key]
                for key in (
                    "eventType",
                    "aggregateId",
                    "anchorReservationId",
                    "anchorPrepareReceiptDigest",
                    "anchorCandidateProjectionDigest",
                    "requiredAnchorVersion",
                    "deliveryGate",
                    "snapshotContentHash",
                    "hostAuthorityResourceVersion",
                    "availabilityAuthorityResourceVersion",
                )
            },
        )

        def availability_projection(value: dict[str, Any]) -> str:
            projected = copy.deepcopy(value)
            projected["lastMutationDigest"] = None
            return bytes_digest(projected)

        def audit_projection(value: dict[str, Any]) -> str:
            projected = copy.deepcopy(value)
            projected["mutationSetHash"] = None
            projected["auditDigest"] = None
            return bytes_digest(projected)

        def outbox_projection(value: dict[str, Any]) -> str:
            projected = copy.deepcopy(value)
            projected["mutationSetHash"] = None
            projected["outboxDigest"] = None
            return bytes_digest(projected)

        mutations = [
            {
                "mutationKind": "UPDATE",
                "entityType": "ENTITY-AVAILABILITY-AUTHORITY",
                "recordId": "availability-1",
                "digestProjection": (
                    "AVAILABILITY_AUTHORITY_LAST_MUTATION_DIGEST_NULL"
                ),
                "beforeDigestOrNull": ONE_DIGEST,
                "afterDigestOrNull": availability_projection(availability),
            },
            {
                "mutationKind": "INSERT",
                "entityType": "ENTITY-HOST-SNAPSHOT-PUBLICATION-AUDIT",
                "recordId": "audit-1",
                "digestProjection": (
                    "PUBLICATION_AUDIT_MUTATION_SET_AND_AUDIT_DIGEST_NULL"
                ),
                "beforeDigestOrNull": None,
                "afterDigestOrNull": audit_projection(audit),
            },
            {
                "mutationKind": "INSERT",
                "entityType": "ENTITY-HOST-SNAPSHOT-PUBLICATION-OUTBOX",
                "recordId": "outbox-1",
                "digestProjection": (
                    "PUBLICATION_OUTBOX_MUTATION_SET_AND_OUTBOX_DIGEST_NULL"
                ),
                "beforeDigestOrNull": None,
                "afterDigestOrNull": outbox_projection(outbox),
            },
        ]
        mutations.sort(
            key=lambda value: canonical(
                [
                    value["entityType"],
                    value["recordId"],
                    value["mutationKind"],
                ]
            )
        )
        mutation_set_hash = domain_digest(
            "QMAN-DIRECTPATH/HOST-SNAPSHOT-MUTATION-SET/V1",
            mutations,
        )
        availability["lastMutationDigest"] = mutation_set_hash
        audit["mutationSetHash"] = mutation_set_hash
        outbox["mutationSetHash"] = mutation_set_hash
        audit["auditDigest"] = null_field_digest(
            "QMAN-DIRECTPATH/HOST-SNAPSHOT-PUBLICATION-AUDIT/V1",
            audit,
            "auditDigest",
        )
        outbox["outboxDigest"] = null_field_digest(
            "QMAN-DIRECTPATH/HOST-SNAPSHOT-PUBLICATION-OUTBOX/V1",
            outbox,
            "outboxDigest",
        )
        for definition, instance in (
            ("publicationAuditRecord", audit),
            ("publicationOutboxRecord", outbox),
        ):
            Draft202012Validator(
                {
                    "$schema": self.trace["$schema"],
                    "$defs": self.trace["$defs"],
                    "$ref": f"#/$defs/{definition}",
                },
                registry=self.registry,
            ).validate(instance)

        self.assertEqual(
            next(
                mutation["afterDigestOrNull"]
                for mutation in mutations
                if mutation["entityType"]
                == "ENTITY-AVAILABILITY-AUTHORITY"
            ),
            availability_projection(availability),
        )
        self.assertEqual(
            next(
                mutation["afterDigestOrNull"]
                for mutation in mutations
                if mutation["entityType"]
                == "ENTITY-HOST-SNAPSHOT-PUBLICATION-AUDIT"
            ),
            audit_projection(audit),
        )
        self.assertEqual(
            next(
                mutation["afterDigestOrNull"]
                for mutation in mutations
                if mutation["entityType"]
                == "ENTITY-HOST-SNAPSHOT-PUBLICATION-OUTBOX"
            ),
            outbox_projection(outbox),
        )

        commit = {
            "mutationSetHash": mutation_set_hash,
            "availabilityAuthorityAfterInstanceSha256": bytes_digest(
                availability
            ),
            "auditRecordInstanceSha256": bytes_digest(audit),
            "outboxRecordInstanceSha256": bytes_digest(outbox),
            "commitRecordDigest": ZERO_DIGEST,
        }
        commit["commitRecordDigest"] = null_field_digest(
            "QMAN-DIRECTPATH/HOST-SNAPSHOT-REPOSITORY-COMMIT/V1",
            commit,
            "commitRecordDigest",
        )
        trace = {
            "commitRecord": commit,
            "traceDigest": ZERO_DIGEST,
        }
        trace["traceDigest"] = null_field_digest(
            "QMAN-DIRECTPATH/HOST-SNAPSHOT-PUBLICATION-TRACE/V1",
            trace,
            "traceDigest",
        )
        self.assertNotIn("CaseCompletionRecord", canonical(trace).decode())
        self.assertNotIn("ExecutionEvidenceIndex", canonical(trace).decode())

        tampered = copy.deepcopy(availability)
        tampered["resourceVersion"] += 1
        self.assertNotEqual(
            availability_projection(availability),
            availability_projection(tampered),
        )
        hash_rules = " ".join(self.trace["x-qmanHashRules"])
        for token in (
            "AVAILABILITY_AUTHORITY_LAST_MUTATION_DIGEST_NULL",
            "PUBLICATION_AUDIT_MUTATION_SET_AND_AUDIT_DIGEST_NULL",
            "PUBLICATION_OUTBOX_MUTATION_SET_AND_OUTBOX_DIGEST_NULL",
            "HOST-SNAPSHOT-PUBLICATION-AUDIT/V1",
            "HOST-SNAPSHOT-PUBLICATION-OUTBOX/V1",
            "HOST-SNAPSHOT-REPOSITORY-COMMIT/V1",
            "HOST-SNAPSHOT-VISIBILITY-PROBE/V1",
        ):
            self.assertIn(token, hash_rules)
        atomic_rules = " ".join(self.trace["x-qmanAtomicCommitRules"])
        self.assertIn(
            "compute the independent outbox payload hash before any mutation projection",
            atomic_rules,
        )

    def test_publication_v1_candidate_authority_and_atomicity_surface_is_closed(
        self,
    ) -> None:
        self.assertTrue(
            {
                "capabilityPolicy",
                "capabilityPolicyAuthority",
                "candidateDeviceRecords",
                "deviceRecords",
            }
            <= set(self.trace["required"])
        )
        self.assertEqual(
            4096,
            self.trace["$defs"]["deviceRecordArtifactSet"]["maxItems"],
        )

        transaction = self.trace["$defs"]["repositoryTransaction"]
        self.assertTrue(
            {
                "expectedHostAuthorityResourceVersion",
                "expectedAvailabilityAuthorityResourceVersion",
                "expectedCapabilityPolicyAuthorityResourceVersion",
                "expectedCapabilityPolicyHash",
                "expectedFreshnessPolicyAuthorityResourceVersion",
                "expectedFreshnessPolicyHash",
                "expectationHash",
                "resolvedAuthorityVectorHash",
            }
            <= set(transaction["required"])
        )
        rollback = self.trace["$defs"]["snapshotRollbackAuthority"]
        self.assertEqual(
            {
                "beforeOrNull",
                "beforeFreshnessOrNull",
                "rollbackAuthorityPreflight",
                "preparedOrNull",
                "after",
                "afterFreshness",
            },
            set(rollback["required"]),
        )
        self.assertNotIn("freshness", rollback["properties"])

        expected_record_ids = {
            "ENTITY-DEVICE-RECORD": (
                "deviceRecordArtifact.recordBinding.deviceRecordHash"
            ),
            "ENTITY-HOST-SNAPSHOT": "hostSnapshotArtifact.state.contentHash",
            "ENTITY-HOST-AUTHORITY": "hostAuthorityArtifact.state.hostId",
            "ENTITY-AVAILABILITY-AUTHORITY": (
                "availabilityAuthorityArtifact.state.availabilityAuthorityId"
            ),
            "ENTITY-HOST-SNAPSHOT-PUBLICATION-AUDIT": (
                "publicationAuditRecord.state.auditEventId"
            ),
            "ENTITY-HOST-SNAPSHOT-PUBLICATION-OUTBOX": (
                "publicationOutboxRecord.state.outboxEventId"
            ),
            "ENTITY-HOST-SNAPSHOT-PUBLICATION-COMMIT": (
                "repositoryCommitRecord.state.commitId"
            ),
        }
        self.assertEqual(
            expected_record_ids,
            self.trace["$defs"]["mutation"]["x-qmanRecordIdProjection"],
        )
        self.assertEqual(
            4102,
            self.trace["$defs"]["commitWitnessBase"]["properties"]["mutations"][
                "maxItems"
            ],
        )
        self.assertEqual(
            {"type": "null"},
            self.trace["$defs"]["publicationAuditRecord"]["properties"][
                "priorAuditDigestOrNull"
            ],
        )
        self.assertEqual(
            {"const": 1},
            self.trace["$defs"]["publicationOutboxRecord"]["properties"][
                "resourceVersion"
            ],
        )
        self.assertEqual(
            {
                "committedDecisions": [
                    "GENESIS_COMMITTED",
                    "INCARNATION_GENESIS_COMMITTED",
                    "SUCCESSOR_COMMITTED",
                    "REFRESH_COMMITTED",
                ],
                "committedPersistedAfterSource": "candidateDeviceRecords",
                "noChangePersistedAfterSource": "currentDeviceRecordsOrNull",
                "persistedAfterTarget": "deviceRecords",
                "candidateAlwaysRetained": True,
                "equalityProfile": "BYTE_EQUAL_CANONICAL_ARTIFACT_ARRAY",
            },
            self.trace["x-qmanPersistedRecordSelection"],
        )

        capture_rules = " ".join(self.trace["x-qmanCaptureClosureRules"])
        publication_rules = " ".join(self.trace["x-qmanPublicationRules"])
        atomic_rules = " ".join(self.trace["x-qmanAtomicCommitRules"])
        self.assertIn(
            "candidateDeviceRecords is the complete FULL_HOST", capture_rules
        )
        self.assertIn(
            "deviceRecords byte-equals currentDeviceRecordsOrNull",
            publication_rules,
        )
        self.assertIn("exactly deviceRecords length plus six", atomic_rules)

    def test_four_authority_cas_hash_preimages_are_closed_and_sensitive(
        self,
    ) -> None:
        expectation_definition = self.trace["$defs"][
            "snapshotPublicationCasExpectation"
        ]
        expectation = {
            "subjectType": "HOST_SNAPSHOT_PUBLICATION_CAS_EXPECTATION",
            "schemaVersion": 1,
            "repositoryId": "repository-1",
            "hostAuthority": {
                "authorityId": "host-1",
                "resourceVersion": 1,
                "instanceBytesSha256": ZERO_DIGEST,
            },
            "availabilityAuthority": {
                "authorityId": "availability-1",
                "resourceVersion": 2,
                "instanceBytesSha256": ONE_DIGEST,
            },
            "capabilityPolicyAuthority": {
                "authorityId": "capability-policy-current",
                "resourceVersion": 3,
                "policyHash": ONE_DIGEST,
                "instanceBytesSha256": TWO_DIGEST,
            },
            "freshnessPolicyAuthority": {
                "authorityId": "freshness-policy-current",
                "resourceVersion": 4,
                "policyHash": TWO_DIGEST,
                "instanceBytesSha256": ZERO_DIGEST,
            },
            "expectationHash": ZERO_DIGEST,
        }
        expectation_rule = expectation_definition["x-qmanDigestProjection"]
        expectation["expectationHash"] = null_field_digest(
            expectation_rule["digestDomain"],
            expectation,
            expectation_rule["digestField"],
        )
        Draft202012Validator(
            {
                "$schema": self.trace["$schema"],
                "$defs": self.trace["$defs"],
                "$ref": "#/$defs/snapshotPublicationCasExpectation",
            },
            registry=self.registry,
        ).validate(expectation)
        expectation_mutations = (
            (("hostAuthority", "resourceVersion"), 2),
            (("availabilityAuthority", "resourceVersion"), 3),
            (("capabilityPolicyAuthority", "resourceVersion"), 4),
            (("freshnessPolicyAuthority", "resourceVersion"), 5),
            (("capabilityPolicyAuthority", "policyHash"), ZERO_DIGEST),
            (("freshnessPolicyAuthority", "policyHash"), ONE_DIGEST),
            (("hostAuthority", "instanceBytesSha256"), ONE_DIGEST),
            (("availabilityAuthority", "instanceBytesSha256"), TWO_DIGEST),
            (
                ("capabilityPolicyAuthority", "instanceBytesSha256"),
                ZERO_DIGEST,
            ),
            (
                ("freshnessPolicyAuthority", "instanceBytesSha256"),
                ONE_DIGEST,
            ),
            (("repositoryId",), "repository-2"),
        )
        for path, replacement in expectation_mutations:
            tampered = copy.deepcopy(expectation)
            _replace_at_path(tampered, path, replacement)
            self.assertNotEqual(
                expectation["expectationHash"],
                null_field_digest(
                    expectation_rule["digestDomain"],
                    tampered,
                    expectation_rule["digestField"],
                ),
                path,
            )
        for authority_name in (
            "hostAuthority",
            "availabilityAuthority",
            "capabilityPolicyAuthority",
            "freshnessPolicyAuthority",
        ):
            tampered = copy.deepcopy(expectation)
            tampered[authority_name]["resourceVersion"] += 1
            self.assertNotEqual(
                expectation["expectationHash"],
                null_field_digest(
                    expectation_rule["digestDomain"],
                    tampered,
                    expectation_rule["digestField"],
                ),
                authority_name,
            )

        resolved_definition = self.trace["$defs"][
            "snapshotPublicationResolvedAuthorityVector"
        ]
        resolved = {
            "subjectType": (
                "HOST_SNAPSHOT_PUBLICATION_RESOLVED_AUTHORITY_VECTOR"
            ),
            "schemaVersion": 1,
            "repositoryId": "repository-1",
            "transactionId": "transaction-1",
            "outcome": "NO_CHANGE",
            "commitIdOrNull": None,
            "hostAuthorityInstanceSha256": ZERO_DIGEST,
            "availabilityAuthorityInstanceSha256": ONE_DIGEST,
            "capabilityPolicyAuthorityInstanceSha256": TWO_DIGEST,
            "freshnessPolicyAuthorityInstanceSha256": ZERO_DIGEST,
            "resolvedAuthorityVectorHash": ZERO_DIGEST,
        }
        resolved_rule = resolved_definition["x-qmanDigestProjection"]
        resolved["resolvedAuthorityVectorHash"] = null_field_digest(
            resolved_rule["digestDomain"],
            resolved,
            resolved_rule["digestField"],
        )
        resolved_validator = Draft202012Validator(
            {
                "$schema": self.trace["$schema"],
                "$defs": self.trace["$defs"],
                "$ref": "#/$defs/snapshotPublicationResolvedAuthorityVector",
            },
            registry=self.registry,
        )
        resolved_validator.validate(resolved)
        committed_without_id = copy.deepcopy(resolved)
        committed_without_id["outcome"] = "COMMITTED"
        self.assertTrue(
            list(resolved_validator.iter_errors(committed_without_id))
        )
        no_change_with_id = copy.deepcopy(resolved)
        no_change_with_id["commitIdOrNull"] = "commit-1"
        self.assertTrue(list(resolved_validator.iter_errors(no_change_with_id)))
        committed = copy.deepcopy(resolved)
        committed["outcome"] = "COMMITTED"
        committed["commitIdOrNull"] = "commit-1"
        committed["resolvedAuthorityVectorHash"] = null_field_digest(
            resolved_rule["digestDomain"],
            committed,
            resolved_rule["digestField"],
        )
        resolved_validator.validate(committed)
        for field in (
            "hostAuthorityInstanceSha256",
            "availabilityAuthorityInstanceSha256",
            "capabilityPolicyAuthorityInstanceSha256",
            "freshnessPolicyAuthorityInstanceSha256",
        ):
            tampered = copy.deepcopy(resolved)
            tampered[field] = (
                ONE_DIGEST if resolved[field] != ONE_DIGEST else TWO_DIGEST
            )
            self.assertNotEqual(
                resolved["resolvedAuthorityVectorHash"],
                null_field_digest(
                    resolved_rule["digestDomain"],
                    tampered,
                    resolved_rule["digestField"],
                ),
                field,
            )

    def test_result_refs_replay_actual_retained_artifacts(self) -> None:
        output = self.payload["$defs"]["output_OP_CAPTURE_HOST_SNAPSHOT"]
        projection_rule = output["x-qmanPublicationTraceProjectionRule"]
        for token in (
            "hostSnapshotAfter.instanceBytesSha256",
            "hostAuthorityAfter.instanceBytesSha256",
            "snapshotRollbackAuthority.after.state.anchorDigest",
            "snapshotRollbackAuthority.after.instanceBytesSha256",
            "snapshotRollbackAuthority.afterFreshness.instanceBytesSha256",
            "providerSemanticProjection.providerFactsDigest",
        ):
            self.assertIn(token, projection_rule)
        request = self.payload["$defs"]["requestBody_OP_CAPTURE_HOST_SNAPSHOT"]
        self.assertTrue(
            {
                "currentAvailabilityAuthority",
                "capabilityPolicy",
                "capabilityPolicyAuthority",
                "hostSnapshotRollbackAnchorOrNull",
                "hostSnapshotAnchorFreshnessOrNull",
                "snapshotFreshnessPolicy",
                "snapshotFreshnessPolicyAuthority",
            }
            <= set(request["required"])
        )
        self.assertTrue(
            {
                "freshnessDecision",
                "snapshotRollbackAnchor",
                "snapshotAnchorFreshness",
            }
            <= set(output["required"])
        )
        self.assertIn("beforeOrNull", request["x-qmanPublicationReadSetBindingRule"])
        self.assertIn(
            "beforeFreshnessOrNull",
            request["x-qmanPublicationReadSetBindingRule"],
        )
        self.assertIn(
            "snapshotRollbackAuthority.after",
            output["x-qmanPublicationTraceProjectionRule"],
        )
        self.assertIn(
            "snapshotRollbackAuthority.afterFreshness",
            output["x-qmanPublicationTraceProjectionRule"],
        )

    def test_capture_payload_rejects_split_anchor_and_invalid_cas_outcomes(
        self,
    ) -> None:
        def entity_ref(entity_type: str, entity_id: str = "entity-1") -> dict[str, Any]:
            return {
                "entityType": entity_type,
                "entityId": entity_id,
                "resourceVersion": 1,
                "generationOrNull": None,
                "contentHash": ZERO_DIGEST,
            }

        def document_ref(
            document_kind: str,
            document_id: str = "document-1",
        ) -> dict[str, Any]:
            return {
                "documentKind": document_kind,
                "documentId": document_id,
                "documentVersion": 1,
                "canonicalProfile": "CANONICAL-JSON-V1",
                "schemaRef": "contracts/document.schema.json",
                "contentHash": ZERO_DIGEST,
            }

        request_validator = Draft202012Validator(
            {
                "$schema": self.payload["$schema"],
                "$defs": self.payload["$defs"],
                "$ref": "#/$defs/requestBody_OP_CAPTURE_HOST_SNAPSHOT",
            }
        )
        request = {
            "hostId": "host-1",
            "hostBootIdentity": {
                "hostId": "host-1",
                "kernelBootId": "boot-1",
                "hostEpoch": 1,
            },
            "currentHostAuthority": entity_ref(
                "ENTITY-HOST-AUTHORITY", "host-1"
            ),
            "currentAvailabilityAuthority": entity_ref(
                "ENTITY-AVAILABILITY-AUTHORITY", "availability-1"
            ),
            "capabilityPolicy": document_ref("CAPABILITY_POLICY"),
            "capabilityPolicyAuthority": entity_ref(
                "ENTITY-CAPABILITY-POLICY-AUTHORITY",
                "capability-policy-current",
            ),
            "trustedKeyRing": document_ref("TRUST_KEY_RING"),
            "trustRootSet": document_ref("TRUST_ROOT_SET"),
            "rollbackAnchor": document_ref("TRUST_ROLLBACK_ANCHOR"),
            "hostSnapshotRollbackAnchorOrNull": None,
            "hostSnapshotAnchorFreshnessOrNull": None,
            "snapshotFreshnessPolicy": document_ref(
                "HOST_SNAPSHOT_FRESHNESS_POLICY"
            ),
            "snapshotFreshnessPolicyAuthority": entity_ref(
                "ENTITY-HOST-SNAPSHOT-FRESHNESS-POLICY-AUTHORITY",
                "freshness-policy-current",
            ),
        }
        request_validator.validate(request)
        split = copy.deepcopy(request)
        split["hostSnapshotRollbackAnchorOrNull"] = document_ref(
            "HOST_SNAPSHOT_ROLLBACK_ANCHOR"
        )
        self.assertTrue(list(request_validator.iter_errors(split)))
        split = copy.deepcopy(request)
        split["hostSnapshotAnchorFreshnessOrNull"] = document_ref(
            "ANCHOR_FRESHNESS_ENVELOPE"
        )
        self.assertTrue(list(request_validator.iter_errors(split)))
        predecessor = copy.deepcopy(request)
        predecessor["hostSnapshotRollbackAnchorOrNull"] = document_ref(
            "HOST_SNAPSHOT_ROLLBACK_ANCHOR"
        )
        predecessor["hostSnapshotAnchorFreshnessOrNull"] = document_ref(
            "ANCHOR_FRESHNESS_ENVELOPE"
        )
        request_validator.validate(predecessor)

        cas_validator = Draft202012Validator(
            {
                "$schema": self.payload["$schema"],
                "$defs": self.payload["$defs"],
                "$ref": "#/$defs/snapshotPublicationCasResult",
            }
        )
        no_change_cas = {
            "decision": "NO_CHANGE",
            "expectationHashOrNull": ZERO_DIGEST,
            "committedAuthorityHashOrNull": ONE_DIGEST,
            "expectedHostAuthorityResourceVersionOrNull": 1,
            "expectedAvailabilityAuthorityResourceVersionOrNull": 1,
            "expectedCapabilityPolicyAuthorityResourceVersionOrNull": 1,
            "expectedCapabilityPolicyHashOrNull": ONE_DIGEST,
            "expectedFreshnessPolicyAuthorityResourceVersionOrNull": 1,
            "expectedFreshnessPolicyHashOrNull": TWO_DIGEST,
            "committedHostAuthorityResourceVersionOrNull": 1,
            "committedAvailabilityAuthorityResourceVersionOrNull": 1,
            "mutationSetHashOrNull": None,
            "commitRecordDigestOrNull": None,
            "publicationMutationCount": 0,
            "conflicts": [],
        }
        cas_validator.validate(no_change_cas)
        for field in ("expectationHashOrNull", "committedAuthorityHashOrNull"):
            invalid = copy.deepcopy(no_change_cas)
            invalid[field] = None
            self.assertTrue(list(cas_validator.iter_errors(invalid)), field)

        conflict = {
            **no_change_cas,
            "decision": "CONFLICT",
            "committedAuthorityHashOrNull": None,
            "committedHostAuthorityResourceVersionOrNull": None,
            "committedAvailabilityAuthorityResourceVersionOrNull": None,
            "conflicts": [
                {
                    "entityType": "ENTITY-HOST-AUTHORITY",
                    "entityId": "host-1",
                    "expectedResourceVersionOrNull": 1,
                    "observedResourceVersionOrNull": 2,
                    "expectedGenerationOrNull": None,
                    "observedGenerationOrNull": None,
                    "conflictReason": "VERSION_MISMATCH",
                }
            ],
        }
        cas_validator.validate(conflict)
        missing_expectation = copy.deepcopy(conflict)
        missing_expectation["expectationHashOrNull"] = None
        self.assertTrue(list(cas_validator.iter_errors(missing_expectation)))
        non_authority = copy.deepcopy(conflict)
        non_authority["conflicts"][0]["entityType"] = "ENTITY-DEVICE-RECORD"
        self.assertTrue(list(cas_validator.iter_errors(non_authority)))
        cas_schema = self.payload["$defs"]["snapshotPublicationCasResult"]
        self.assertEqual(4, cas_schema["properties"]["conflicts"]["maxItems"])
        self.assertEqual(
            4102,
            cas_schema["properties"]["publicationMutationCount"]["maximum"],
        )

        result_validator = Draft202012Validator(
            {
                "$schema": self.payload["$schema"],
                "$defs": self.payload["$defs"],
                "$ref": "#/$defs/resultBody_OP_CAPTURE_HOST_SNAPSHOT",
            }
        )
        output = {
            "hostSnapshot": document_ref("HOST_SNAPSHOT"),
            "snapshotContentHash": ZERO_DIGEST,
            "inventorySignature": document_ref("HOST_INVENTORY_SIGNATURE"),
            "advancedHostAuthority": entity_ref(
                "ENTITY-HOST-AUTHORITY", "host-1"
            ),
            "factProvenanceSetHash": ONE_DIGEST,
            "freshnessDecision": {
                "policyId": "freshness-policy-1",
                "policyVersion": 1,
                "policyDigest": TWO_DIGEST,
                "policyAuthorityResourceVersion": 1,
                "evaluatedAt": T1,
                "evaluationDisposition": "GENESIS_NO_CURRENT",
                "maximumSnapshotAgeMicros": 1,
                "maximumMandatoryEvidenceAgeMicros": 1,
                "currentSnapshotCapturedAtOrNull": None,
                "oldestMandatoryEvidenceObservedAtOrNull": None,
                "refreshRequired": False,
                "decisionDigest": ZERO_DIGEST,
            },
            "snapshotRollbackAnchor": document_ref(
                "HOST_SNAPSHOT_ROLLBACK_ANCHOR"
            ),
            "snapshotAnchorFreshness": document_ref(
                "ANCHOR_FRESHNESS_ENVELOPE"
            ),
        }
        success = {
            "outcome": "SUCCEEDED",
            "outputOrNull": output,
            "errorOrNull": None,
            "progressOrNull": None,
            "casResult": no_change_cas,
        }
        result_validator.validate(success)
        invalid_success = copy.deepcopy(success)
        invalid_success["casResult"] = conflict
        self.assertTrue(list(result_validator.iter_errors(invalid_success)))

    def test_payload_raw_hash_is_pinned_everywhere(self) -> None:
        payload_hash = "sha256:" + hashlib.sha256(
            (
                ROOT / "contracts/directpath-operation-payload.schema.json"
            ).read_bytes()
        ).hexdigest()
        self.assertEqual(
            payload_hash,
            self.envelope["$defs"]["requestEnvelope"]["properties"][
                "payloadSchemaSha256"
            ]["const"],
        )
        self.assertEqual(
            payload_hash,
            self.envelope["$defs"]["resultEnvelope"]["properties"][
                "payloadSchemaSha256"
            ]["const"],
        )
        payload_ref = self.scenario_schema["$defs"]["payloadBindingBase"]
        self.assertEqual(
            payload_hash,
            payload_ref["properties"]["payloadSchemaSha256"]["const"],
        )
        example = load(
            "handoff/examples/S05-legacy-qemu-start-failure-clean-rollback.json"
        )

        def values(node: object) -> Iterable[str]:
            if isinstance(node, dict):
                for key, value in node.items():
                    if key == "payloadSchemaSha256" and isinstance(value, str):
                        yield value
                    yield from values(value)
            elif isinstance(node, list):
                for value in node:
                    yield from values(value)

        self.assertEqual({payload_hash}, set(values(example)))

    def test_c00_and_portable_closure_keep_product_blocked(self) -> None:
        c00 = next(
            record for record in self.registry_c["records"] if record["id"] == "C00"
        )
        self.assertEqual("PRODUCT", c00["scope"])
        self.assertEqual("IMPLEMENTATION_BLOCKED", c00["status"])
        self.assertEqual("G1", c00["targetMilestone"])
        required_refs = set(c00["requiredArtifactSchemaRefs"])
        self.assertTrue(
            {
                "contracts/directpath-host-snapshot-publication-trace.schema.json",
                "contracts/directpath-host-snapshot-rollback-anchor.schema.json",
                "contracts/directpath-anchor-freshness-envelope.schema.json",
                "contracts/directpath-trust-root-set.schema.json",
                "contracts/directpath-trust-key-ring.schema.json",
                "contracts/directpath-trust-key-ring-history.schema.json",
                "contracts/directpath-trust-rollback-anchor.schema.json",
            }
            <= required_refs
        )
        self.assertTrue(
            {
                "contracts/directpath-host-snapshot-publication-trace.schema.json",
                "contracts/directpath-host-snapshot-rollback-anchor.schema.json",
            }
            <= set(self.portable["normativeSources"])
        )
        hash_subjects = {
            entry["subject"]
            for entry in self.portable["canonicalizationContract"][
                "hashSubjects"
            ]
        }
        self.assertTrue(
            {
                "HostInventoryCaptureBatch",
                "HostDeviceSemanticProjection",
                "HostTopologySemanticProjection",
                "HostProviderSemanticProjection",
                "HostSnapshotNoChangeProjection",
                "HostSnapshotFreshnessDecision",
                "HostSnapshotRollbackAnchor",
                "HostSnapshotPublicationAuditRecord",
                "HostSnapshotPublicationOutboxRecord",
                "HostSnapshotRepositoryCommitRecord",
                "HostSnapshotVisibilityProbe",
                "HostSnapshotPublicationTrace",
            }
            <= hash_subjects
        )
        binding = self.trace["$defs"]["productEvidenceBinding"]
        self.assertEqual(
            {
                "mappingCoreIdOrNull",
                "caseContractDigestOrNull",
                "targetBuildAttestationDigestOrNull",
                "runnerManifestDigestOrNull",
            },
            set(binding["required"]),
        )
        serialized_binding = json.dumps(binding, sort_keys=True)
        self.assertNotIn("CaseCompletionRecord", serialized_binding)
        self.assertNotIn("ExecutionEvidenceIndex", serialized_binding)
        completion = " ".join(self.trace["x-qmanCompletionRules"])
        self.assertIn("point one-way to traceDigest", completion)
        self.assertIn("never close C00", completion)
        self.assertIn(
            "REFERENCE_SQLITE_HOST_SNAPSHOT_PUBLICATION_COMPONENT_ONLY",
            completion,
        )

    def test_recovery_and_zero_partial_write_rules_are_closed(self) -> None:
        rollback_rules = " ".join(
            self.trace["x-qmanRollbackAndFreshnessRules"]
        )
        anchor_rule = self.anchor["x-qmanPrepareCommitRule"]
        preflight_rule = self.anchor["x-qmanRollbackAuthorityPreflightRule"]
        for token in (
            "prepareReceipt.reservationId",
            "candidateProjectionDigest",
            "last COMMITTED anchor",
            "NO_CHANGE",
        ):
            self.assertIn(token, rollback_rules)
        for token in (
            "reservationId",
            "prepareReceipt.receiptDigest",
            "candidateProjectionDigest",
            "exact COMMITTED anchor",
            "NO_CHANGE",
        ):
            self.assertIn(token, anchor_rule)
        self.assertIn(
            "repeated finalize returns the same COMMITTED anchor/receipt",
            rollback_rules,
        )
        self.assertIn(
            "finalize remains permitted after expiresAt and is idempotent",
            anchor_rule,
        )
        self.assertIn("elapsed TTL alone is insufficient", rollback_rules)
        self.assertIn("elapsed TTL alone is never proof", anchor_rule)
        self.assertIn("unresolvedReservationCount=0", preflight_rule)
        self.assertIn("fresh verifierNonce", preflight_rule)
        self.assertIn(
            "rollbackAuthorityPreflightReceiptDigest",
            self.anchor["$defs"]["prepareReceipt"]["required"],
        )

        preflight = {
            "schemaVersion": 1,
            "receiptType": "HOST_SNAPSHOT_ROLLBACK_AUTHORITY_PREFLIGHT",
            "receiptId": "preflight-1",
            "hostId": "host-1",
            "authorityId": "external-host-snapshot-authority",
            "predecessorAnchorDigestOrNull": ONE_DIGEST,
            "checkedAt": T0,
            "expiresAt": T2,
            "verifierNonce": "A" * 22,
            "unresolvedReservationCount": 0,
            "trustRootDigest": ONE_DIGEST,
            "receiptDigest": TWO_DIGEST,
            "rootSignatures": [root_signature()],
        }
        preflight_validator = Draft202012Validator(
            {
                "$schema": self.anchor["$schema"],
                "$defs": self.anchor["$defs"],
                "$ref": "#/$defs/rollbackAuthorityPreflightReceipt",
            }
        )
        preflight_validator.validate(preflight)
        invalid_preflight = copy.deepcopy(preflight)
        invalid_preflight["unresolvedReservationCount"] = 1
        self.assertTrue(list(preflight_validator.iter_errors(invalid_preflight)))

        self.assertEqual(
            {
                "beforeOrNull",
                "beforeFreshnessOrNull",
                "rollbackAuthorityPreflight",
                "preparedOrNull",
                "after",
                "afterFreshness",
            },
            set(
                self.trace["$defs"]["snapshotRollbackAuthority"]["required"]
            ),
        )
        self.assertNotIn(
            '"freshness"',
            json.dumps(
                self.trace["$defs"]["snapshotRollbackAuthority"],
                sort_keys=True,
            ),
        )
        self.assertIn("pairwise distinct", rollback_rules)
        for rules in (rollback_rules, anchor_rule):
            self.assertNotIn(
                "abort the reservation or let it expire by TTL",
                rules,
            )
        atomic_rules = " ".join(self.trace["x-qmanAtomicCommitRules"])
        self.assertIn("no extra mutation exists", atomic_rules)
        self.assertIn("BEFORE probe", atomic_rules)
        self.assertIn("AFTER probe", atomic_rules)
        self.assertIn("zero", " ".join(self.trace["x-qmanAtomicCommitRules"]).lower())


if __name__ == "__main__":
    unittest.main()
