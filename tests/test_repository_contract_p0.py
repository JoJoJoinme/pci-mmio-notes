from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
import unittest

from jsonschema import Draft202012Validator
from tools import validate_portable_handoff as handoff_validator


ROOT = Path(__file__).resolve().parents[1]
CAS_EXPECTATION_SCHEMA_REF = (
    "contracts/directpath-operation-payload.schema.json"
    "#/$defs/casExpectation"
)
NEW_AUTHORITY_ENTITY_TYPES = {
    "ENTITY-CAPABILITY-POLICY-AUTHORITY",
    "ENTITY-AVAILABILITY-AUTHORITY",
}
NEW_OPERATION_ENTITY_TYPES = NEW_AUTHORITY_ENTITY_TYPES | {
    "ENTITY-OPERATION-ADMISSION-BINDING",
}
EXACT_OPERATION_CAPABILITY_FIELDS = [
    "operationLeaseId",
    "leaseType",
    "scopeHash",
    "runIdOrIntentId",
    "bundleIds",
    "memberGenerations",
    "hostEpoch",
    "runGenerationOrNull",
    "holderControllerGeneration",
    "operationLeaseResourceVersion",
    "admissionBindingHashOrNull",
]


def load(relative_path: str) -> dict[str, Any]:
    return json.loads((ROOT / relative_path).read_text(encoding="utf-8"))


def assignment_binding_condition(schema: dict[str, Any]) -> dict[str, Any]:
    for condition in schema.get("allOf", []):
        lease_type = (
            condition.get("if", {})
            .get("properties", {})
            .get("leaseType", {})
        )
        if lease_type.get("const") == "ASSIGNMENT_PREPARE":
            return condition
    raise AssertionError("missing ASSIGNMENT_PREPARE binding condition")


def nested_values(node: object, key: str) -> list[object]:
    values: list[object] = []
    if isinstance(node, dict):
        for child_key, child_value in node.items():
            if child_key == key:
                values.append(child_value)
            values.extend(nested_values(child_value, key))
    elif isinstance(node, list):
        for child in node:
            values.extend(nested_values(child, key))
    return values


def recursive_strings(node: object) -> list[str]:
    values: list[str] = []
    if isinstance(node, dict):
        for child in node.values():
            values.extend(recursive_strings(child))
    elif isinstance(node, list):
        for child in node:
            values.extend(recursive_strings(child))
    elif isinstance(node, str):
        values.append(node)
    return values


def validator_for_definition(
    contract: dict[str, Any],
    definition: str,
) -> Draft202012Validator:
    return Draft202012Validator(
        {
            "$schema": contract["$schema"],
            "$ref": f"#/$defs/{definition}",
            "$defs": contract["$defs"],
        }
    )


class RepositoryP0ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.authority = load(
            "contracts/directpath-authority-entities.schema.json"
        )
        cls.admission = load(
            "contracts/directpath-operation-admission-binding.schema.json"
        )
        cls.envelope = load(
            "contracts/directpath-operation-envelope.schema.json"
        )
        cls.payload = load(
            "contracts/directpath-operation-payload.schema.json"
        )
        cls.committed = load(
            "contracts/directpath-committed-static-admission.schema.json"
        )
        cls.portable = load(
            "contracts/directpath-portable-control-contract.json"
        )

    def test_new_authorities_are_closed_current_pointer_entities(self) -> None:
        authority_refs = {
            entry["$ref"].removeprefix("#/$defs/")
            for entry in self.authority["oneOf"]
        }
        self.assertTrue(NEW_AUTHORITY_ENTITY_TYPES <= authority_refs)
        self.assertTrue(
            NEW_OPERATION_ENTITY_TYPES
            <= set(self.authority["$defs"]["entityId"]["enum"])
        )

        for entity_type in NEW_AUTHORITY_ENTITY_TYPES:
            with self.subTest(entity_type=entity_type):
                schema = self.authority["$defs"][entity_type]
                self.assertEqual(schema["type"], "object")
                self.assertFalse(schema["additionalProperties"])
                self.assertEqual(
                    set(schema["required"]),
                    set(schema["properties"]),
                )

        policy = self.authority["$defs"][
            "ENTITY-CAPABILITY-POLICY-AUTHORITY"
        ]
        self.assertEqual(
            set(policy["required"]),
            {
                "policyAuthorityId",
                "policyId",
                "policyVersion",
                "policyDigest",
                "resourceVersion",
            },
        )

    def test_global_availability_authority_prevents_phantoms(self) -> None:
        availability = self.authority["$defs"][
            "ENTITY-AVAILABILITY-AUTHORITY"
        ]
        self.assertEqual(
            availability["properties"]["authorityScope"]["const"],
            "GLOBAL_DIRECTPATH_AVAILABILITY",
        )
        rules = " ".join(availability["x-qmanCrossFieldRules"]).lower()
        for required_semantic in (
            "every insert, update, or delete",
            "increments this global resourceversion",
            "same serializable transaction",
            "unobserved phantom",
            "host-local",
            "not sufficient availability authority",
        ):
            with self.subTest(required_semantic=required_semantic):
                self.assertIn(required_semantic, rules)

    def test_idempotency_record_has_versioned_cas_lifecycle(self) -> None:
        record = self.authority["$defs"]["ENTITY-IDEMPOTENCY-RECORD"]
        self.assertNotIn("scope", record["required"])
        self.assertNotIn("scope", record["properties"])
        self.assertTrue(
            {
                "operationId",
                "idempotencyScopeHash",
                "idempotencyKey",
            }
            <= set(record["required"])
        )
        self.assertEqual(
            record["properties"]["operationId"]["$ref"],
            "#/$defs/idempotencyOperationId",
        )
        self.assertEqual(
            record["properties"]["idempotencyScopeHash"]["$ref"],
            "#/$defs/digest",
        )
        self.assertIn("resourceVersion", record["required"])
        self.assertEqual(
            record["properties"]["resourceVersion"]["$ref"],
            "#/$defs/positiveVersion",
        )
        rules = " ".join(record["x-qmanLifecycleRules"]).lower()
        for required_semantic in (
            "[operationid,idempotencyscopehash,idempotencykey]",
            "byte-equal",
            "resourceversion 1",
            "compares the exact current resourceversion",
            "resourceversion+1",
            "retry, replay",
            "read-only",
            "expiry cleanup compares the exact resourceversion",
        ):
            with self.subTest(required_semantic=required_semantic):
                self.assertIn(required_semantic, rules)

        operation_validator = validator_for_definition(
            self.authority,
            "idempotencyOperationId",
        )
        operation_validator.validate("OP-STORE-IDEMPOTENT-RESULT")
        operation_validator.validate("STATIC_ADMISSION")
        self.assertTrue(
            list(operation_validator.iter_errors("CALLER_SELECTED_OPERATION"))
        )

    def test_result_and_store_request_preserve_idempotency_scope(
        self,
    ) -> None:
        result = self.envelope["$defs"]["resultEnvelope"]
        self.assertIn("idempotencyScopeHash", result["required"])
        self.assertEqual(
            result["properties"]["idempotencyScopeHash"]["$ref"],
            "#/$defs/digest",
        )
        envelope_rules = " ".join(
            self.envelope["x-qmanCrossFieldRules"]
        )
        self.assertIn("byte-equal request", envelope_rules)
        self.assertIn("idempotencyScopeHash", envelope_rules)

        store_request = self.payload["$defs"][
            "requestBody_OP_STORE_IDEMPOTENT_RESULT"
        ]
        self.assertNotIn("scope", store_request["required"])
        self.assertNotIn("scope", store_request["properties"])
        self.assertTrue(
            {"operationId", "idempotencyScopeHash"}
            <= set(store_request["required"])
        )
        self.assertEqual(
            store_request["properties"]["operationId"]["$ref"],
            "#/$defs/id",
        )
        self.assertEqual(
            store_request["properties"]["idempotencyScopeHash"]["$ref"],
            "#/$defs/digest",
        )
        natural_key_rule = store_request["x-qmanNaturalKeyRule"]
        self.assertIn(
            "[operationId,idempotencyScopeHash,idempotencyKey]",
            natural_key_rule,
        )
        self.assertIn("original accepted REQUEST envelope tuple", natural_key_rule)

    def test_operation_lease_persists_exact_admission_binding(self) -> None:
        lease = self.authority["$defs"]["ENTITY-OPERATION-LEASE"]
        self.assertIn("admissionBindingHashOrNull", lease["required"])
        self.assertEqual(
            lease["properties"]["admissionBindingHashOrNull"]["$ref"],
            "#/$defs/nullableDigest",
        )
        condition = assignment_binding_condition(lease)
        self.assertEqual(
            condition["then"]["properties"][
                "admissionBindingHashOrNull"
            ]["$ref"],
            "#/$defs/digest",
        )
        self.assertEqual(
            condition["else"]["properties"][
                "admissionBindingHashOrNull"
            ]["type"],
            "null",
        )
        rules = " ".join(lease["x-qmanLifecycleRules"])
        self.assertIn("UNIQUE operationLeaseId", rules)
        self.assertIn("created atomically", rules)

    def test_policy_pointer_and_cas_blob_are_closed_in_admission(self) -> None:
        vector = self.admission["$defs"]["currentAuthorityVector"]
        required_policy_fields = {
            "policyAuthorityId",
            "policyId",
            "policyVersion",
            "policyDigest",
            "policyAuthorityResourceVersion",
        }
        self.assertTrue(required_policy_fields <= set(vector["required"]))
        self.assertTrue(
            required_policy_fields <= set(vector["properties"])
        )

        cas_reference = self.admission["properties"][
            "evidenceBlobReferences"
        ]["properties"]["casExpectation"]
        schema_refs = [
            item.get("properties", {})
            .get("schemaRef", {})
            .get("const")
            for item in cas_reference["allOf"]
        ]
        self.assertIn(CAS_EXPECTATION_SCHEMA_REF, schema_refs)

    def test_envelope_and_payload_bind_the_same_lease_pointer(self) -> None:
        for name, contract in (
            ("envelope", self.envelope),
            ("payload", self.payload),
        ):
            with self.subTest(contract=name):
                self.assertTrue(
                    NEW_OPERATION_ENTITY_TYPES
                    <= set(contract["$defs"]["entityType"]["enum"])
                )

        capability = self.envelope["$defs"]["operationLeaseCapability"]
        payload_binding = self.payload["$defs"]["operationLeaseBinding"]
        for name, schema in (
            ("capability", capability),
            ("payload_binding", payload_binding),
        ):
            with self.subTest(schema=name):
                self.assertIn(
                    "admissionBindingHashOrNull",
                    schema["required"],
                )
                condition = assignment_binding_condition(schema)
                self.assertEqual(
                    condition["then"]["properties"][
                        "admissionBindingHashOrNull"
                    ]["$ref"],
                    "#/$defs/digest",
                )
                self.assertEqual(
                    condition["else"]["properties"][
                        "admissionBindingHashOrNull"
                    ]["type"],
                    "null",
                )

        payload_rule = self.payload["x-operationLeaseBindingRule"]
        self.assertIn("exact projection", payload_rule)
        self.assertIn("admissionBindingHashOrNull", payload_rule)
        envelope_rules = " ".join(self.envelope["x-qmanCrossFieldRules"])
        self.assertIn("exact projection", envelope_rules)
        self.assertIn("admissionBindingHashOrNull", envelope_rules)

    def test_assignment_binding_condition_fails_closed_in_all_layers(
        self,
    ) -> None:
        digest = "sha256:" + "a" * 64
        persisted_lease = {
            "operationLeaseId": "lease-a",
            "leaseType": "ASSIGNMENT_PREPARE",
            "scopeHash": digest,
            "runIdOrIntentId": "run-a",
            "bundleIds": [digest],
            "memberGenerations": {"device-a": 1},
            "hostEpoch": 1,
            "runGenerationOrNull": 1,
            "holderControllerGeneration": 1,
            "admissionBindingHashOrNull": digest,
            "state": "ACTIVE",
            "resourceVersion": 1,
        }
        envelope_capability = {
            "operationLeaseId": "lease-a",
            "leaseType": "ASSIGNMENT_PREPARE",
            "scopeHash": digest,
            "runIdOrIntentId": "run-a",
            "bundleIds": [digest],
            "memberGenerations": [
                {"id": "device-a", "generation": 1}
            ],
            "hostEpoch": 1,
            "runGenerationOrNull": 1,
            "holderControllerGeneration": 1,
            "operationLeaseResourceVersion": 1,
            "admissionBindingHashOrNull": digest,
        }
        payload_binding = {
            "operationLeaseId": "lease-a",
            "leaseType": "ASSIGNMENT_PREPARE",
            "scopeHash": digest,
            "holderControllerGeneration": 1,
            "operationLeaseResourceVersion": 1,
            "admissionBindingHashOrNull": digest,
            "capabilityHash": digest,
        }
        layers = (
            (
                validator_for_definition(
                    self.authority,
                    "ENTITY-OPERATION-LEASE",
                ),
                persisted_lease,
            ),
            (
                validator_for_definition(
                    self.envelope,
                    "operationLeaseCapability",
                ),
                envelope_capability,
            ),
            (
                validator_for_definition(
                    self.payload,
                    "operationLeaseBinding",
                ),
                payload_binding,
            ),
        )
        for validator, assignment in layers:
            with self.subTest(layer=assignment.keys()):
                validator.validate(assignment)

                missing_hash = {
                    **assignment,
                    "admissionBindingHashOrNull": None,
                }
                self.assertTrue(
                    list(validator.iter_errors(missing_hash)),
                    "ASSIGNMENT_PREPARE must reject a null binding hash",
                )

                other_lease = {
                    **assignment,
                    "leaseType": "OWNER_TRANSITION",
                    "admissionBindingHashOrNull": None,
                }
                if "runGenerationOrNull" in other_lease:
                    other_lease["runGenerationOrNull"] = None
                validator.validate(other_lease)
                unsafe_other_hash = {
                    **other_lease,
                    "admissionBindingHashOrNull": digest,
                }
                self.assertTrue(
                    list(validator.iter_errors(unsafe_other_hash)),
                    "current non-assignment leases must reject a binding hash",
                )

    def test_envelope_pins_the_exact_payload_schema_bytes(self) -> None:
        payload_path = (
            ROOT / "contracts/directpath-operation-payload.schema.json"
        )
        expected = "sha256:" + hashlib.sha256(
            payload_path.read_bytes()
        ).hexdigest()
        pinned_schemas = nested_values(
            self.envelope,
            "payloadSchemaSha256",
        )
        self.assertEqual(len(pinned_schemas), 2)
        self.assertEqual(
            {schema["const"] for schema in pinned_schemas},
            {expected},
        )

    def test_operation_identity_and_idempotency_modes_match_portable(
        self,
    ) -> None:
        envelope_identities = {}
        for branch in self.envelope["$defs"]["operationIdentity"]["oneOf"]:
            properties = branch["properties"]
            envelope_identities[properties["operationId"]["const"]] = (
                properties["actorPortId"]["const"],
                properties["idempotencyMode"]["const"],
            )
        portable_identities = {
            operation["id"]: (
                operation["ownerPortId"],
                operation["idempotency"],
            )
            for operation in self.portable["backendNeutralOperations"]
        }
        self.assertEqual(envelope_identities, portable_identities)
        self.assertNotIn(
            "NATURAL_KEY_SCOPE_AND_IDEMPOTENCY_KEY",
            self.envelope["$defs"]["idempotencyMode"]["enum"],
        )

    def test_committed_capability_is_byte_field_compatible_with_envelope(
        self,
    ) -> None:
        envelope_capability = self.envelope["$defs"][
            "operationLeaseCapability"
        ]
        committed_capability = self.committed["$defs"][
            "operationLeaseCapability"
        ]
        for capability in (envelope_capability, committed_capability):
            self.assertEqual(
                capability["required"],
                EXACT_OPERATION_CAPABILITY_FIELDS,
            )
            self.assertEqual(
                set(capability["properties"]),
                set(EXACT_OPERATION_CAPABILITY_FIELDS),
            )

        exact_field_text = ", ".join(EXACT_OPERATION_CAPABILITY_FIELDS)
        sealed_texts = [
            text
            for text in recursive_strings(self.portable)
            if "sealed typed operation capability" in text
        ]
        self.assertEqual(len(sealed_texts), 13)
        for text in sealed_texts:
            with self.subTest(text=text):
                self.assertIn(exact_field_text, text)

    def test_command_and_commit_are_normative_closed_hash_subjects(
        self,
    ) -> None:
        required_paths = {
            "contracts/directpath-static-admission-command.schema.json",
            "contracts/directpath-committed-static-admission.schema.json",
        }
        self.assertTrue(
            required_paths <= set(self.portable["normativeSources"])
        )
        closure_paths = {
            item["path"] for item in self.portable["normativeSourceClosure"]
        }
        self.assertTrue(required_paths <= closure_paths)

        subject_paths = {
            item["schemaRef"].split("#", 1)[0]
            for item in self.portable["canonicalizationContract"][
                "hashSubjects"
            ]
        }
        self.assertTrue(required_paths <= subject_paths)

    def test_decoder_declaration_is_not_observed_artifact_coverage(
        self,
    ) -> None:
        typed_schema = "contracts/directpath-capability-policy.schema.json"
        observed = (
            handoff_validator._case_completion_observed_artifact_schema_refs(
                {
                    "artifacts": [
                        {"schemaRefOrNull": typed_schema},
                        {"schemaRefOrNull": None},
                    ]
                }
            )
        )
        self.assertIn(typed_schema, observed)
        self.assertNotIn(
            "contracts/decoder-declaration-only.schema.json",
            observed,
        )


if __name__ == "__main__":
    unittest.main()
