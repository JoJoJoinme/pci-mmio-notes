from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, fields, replace
from datetime import timedelta
import inspect
import unittest

from qman_directpath_core.admission import bind_static_request_policy
from qman_directpath_core.canonical import canonical_json_bytes, sha256_digest
from qman_directpath_core.closure import (
    DependencyAction,
    DependencyKind,
    FactState,
    ResetMethod,
    resolve_dependency_closure,
)
from qman_directpath_core.contracts import ContractSchemas
from qman_directpath_core.errors import DirectPathVerificationError
from qman_directpath_core.inventory_closure_factory import (
    assess_inventory_closure_projection,
    project_verified_closure_facts,
    resolve_static_inventory_closure,
)
from qman_directpath_core.policy import verify_capability_policy
from qman_directpath_core.qualification_profile import (
    VerifiedQualificationProfileContext,
)
from qman_directpath_core.request import verify_static_request
from tests.test_admission import _bound_documents
from tests.test_inventory import CONTRACTS, NOW, InventoryFixture, digest
from tests.test_request import _rehash


def _typed_inputs(
    fixture: InventoryFixture | None = None,
    *,
    pinned: bool = True,
    member_count: int = 1,
    profile: VerifiedQualificationProfileContext | None = None,
):
    selected_fixture = fixture or InventoryFixture()
    request_document, policy_document = _bound_documents()
    canonical_request = request_document["canonicalRequest"]
    records = selected_fixture.records[:member_count]
    members = canonical_request["selector"]["members"][:member_count]
    if len(records) != member_count or len(members) != member_count:
        raise AssertionError("fixture does not contain the requested member count")
    canonical_request["selector"]["members"] = members
    canonical_request["hostAffinity"]["hostId"] = records[0]["hostId"]
    for member, record in zip(members, records, strict=True):
        member["deviceUid"] = record["deviceUid"]
        member["identityFingerprint"] = record["identityFingerprint"]
        member["enrolledHostId"] = record["hostId"]
        member["expectedPhysicalPathProvider"] = copy.deepcopy(
            record["physicalPathProvider"]
        )
        member["expectedPhysicalPath"] = record["physicalPath"]
        member["expectedCurrentBdf"] = record["currentBdf"]
    if pinned:
        constraint = canonical_request["snapshotConstraint"]
        constraint["maximumAgeMicros"] = 60_000_000
        constraint["binding"] = {
            "hostId": selected_fixture.snapshot["hostId"],
            "kernelBootId": selected_fixture.snapshot["kernelBootId"],
            "hostEpoch": selected_fixture.snapshot["hostEpoch"],
            "agentGeneration": selected_fixture.snapshot["agentGeneration"],
            "hostAuthorityResourceVersion": selected_fixture.snapshot[
                "hostAuthorityResourceVersion"
            ],
            "snapshotEpoch": selected_fixture.snapshot["snapshotEpoch"],
            "snapshotContentHash": selected_fixture.snapshot["contentHash"],
        }
    else:
        constraint = {
            "mode": "RESOLVE_CURRENT_AT_OPERATION",
            "maximumAgeMicros": 60_000_000,
        }
        canonical_request["snapshotConstraint"] = constraint
    policy_document["effectiveAt"] = (NOW - timedelta(hours=1)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )
    policy_document["expiresAt"] = (NOW + timedelta(hours=1)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )
    if profile is not None:
        policy_document.update(
            {
                "admissionMode": "PRODUCTION",
                "supportedCatalogDigest": (profile.qualification.catalog_digest),
                "catalogSequence": (profile.qualification.catalog_sequence),
                "trustKeyRingSequence": (profile.qualification.trust.key_ring_sequence),
                "qualificationCaseMatrixHash": (profile.qualification_case_matrix_hash),
            }
        )
    policy_document["policyHash"] = None
    policy_document["policyHash"] = sha256_digest(canonical_json_bytes(policy_document))
    canonical_request["policyBinding"]["policyHash"] = policy_document["policyHash"]
    if profile is not None:
        canonical_request["profileBinding"] = {
            "profileId": profile.profile_id,
            "profileHash": profile.profile_hash,
            "verificationReceiptHash": profile.receipt_digest,
            "requiredSupportStatus": "SUPPORTED",
        }
        canonical_request["requiredGuestAbiClass"] = profile.guest_abi_class
        request_document["requiredGuestAbiClass"] = profile.guest_abi_class
        canonical_request["policyBinding"] = {
            "policyId": policy_document["policyId"],
            "policyVersion": policy_document["policyVersion"],
            "policyHash": policy_document["policyHash"],
            "admissionMode": policy_document["admissionMode"],
            "supportedCatalogDigest": policy_document["supportedCatalogDigest"],
            "catalogSequence": policy_document["catalogSequence"],
            "trustKeyRingSequence": policy_document["trustKeyRingSequence"],
            "qualificationCaseMatrixHash": policy_document[
                "qualificationCaseMatrixHash"
            ],
        }
    selected_fixture.snapshot["policyHash"] = policy_document["policyHash"]
    selected_fixture.reseal()
    if pinned:
        constraint["binding"]["snapshotContentHash"] = selected_fixture.snapshot[
            "contentHash"
        ]
    _rehash(request_document)
    schemas = ContractSchemas(CONTRACTS)
    request = verify_static_request(schemas, request_document)
    policy = verify_capability_policy(
        schemas,
        policy_document,
        verified_at=NOW,
    )
    admission = bind_static_request_policy(request, policy)
    return selected_fixture, selected_fixture.verify(), admission


class InventoryClosureFactoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture, cls.inventory, cls.admission = _typed_inputs()
        cls.assessment = assess_inventory_closure_projection(
            cls.inventory,
            cls.admission,
        )
        cls.facts = project_verified_closure_facts(
            cls.inventory,
            cls.admission,
        )

    def test_projects_all_seven_typed_domains_and_reset_contract(self) -> None:
        assessment = self.assessment
        record = self.fixture.records[0]

        self.assertTrue(assessment.complete)
        self.assertEqual((), assessment.gaps)
        self.assertEqual(
            self.inventory.inventory_verification_receipt_digest,
            assessment.inventory_verification_receipt_digest,
        )
        self.assertEqual(
            self.inventory.inventory_verifier_identity_digest,
            assessment.inventory_verifier_identity_digest,
        )
        self.assertEqual(
            self.admission.request.request_hash,
            assessment.request_provenance_digest,
        )
        self.assertEqual(
            self.admission.policy.policy_hash,
            assessment.policy_provenance_digest,
        )

        device = assessment.device_facts[0]
        self.assertEqual(record["deviceUid"], device.device_uid)
        self.assertEqual(record["deviceRecordHash"], device.device_record_digest)
        self.assertEqual(
            record["generations"]["deviceGeneration"],
            device.device_generation,
        )
        self.assertEqual(
            record["generations"]["resourceVersion"],
            device.resource_version,
        )
        self.assertEqual(
            tuple(sorted(DependencyKind, key=lambda kind: kind.value)),
            tuple(domain.kind for domain in device.domains),
        )
        expected_domains = {
            domain["kind"]: domain for domain in record["dependencyDomains"]
        }
        self.assertEqual(
            expected_domains,
            {domain.kind.value: domain.to_subject() for domain in device.domains},
        )
        self.assertIs(FactState.KNOWN, device.reset_contract.state)
        self.assertTrue(device.reset_contract.supported)
        self.assertIs(
            ResetMethod.PCI_FLR,
            device.reset_contract.selected_method,
        )
        self.assertEqual(
            record["resetContract"]["provenanceDigest"],
            device.reset_contract.provenance_digest,
        )
        with self.assertRaises(FrozenInstanceError):
            device.device_generation = 3

    def test_factory_derives_closed_receipt_and_identity_only_from_context(
        self,
    ) -> None:
        parameters = inspect.signature(project_verified_closure_facts).parameters
        self.assertEqual(
            tuple(parameters),
            (
                "inventory",
                "admission",
            ),
        )
        for forbidden in (
            "request_provenance_digest",
            "policy_provenance_digest",
            "payload_device_uids",
            "limits",
            "snapshot_digest",
            "verification_receipt_digest",
            "inventory_verification_receipt_digest",
            "verifier_identity_digest",
            "inventory_verifier_identity_digest",
        ):
            self.assertNotIn(forbidden, parameters)
            with self.subTest(forbidden=forbidden):
                with self.assertRaises(TypeError):
                    project_verified_closure_facts(
                        self.inventory,
                        self.admission,
                        **{forbidden: digest(f"caller-forged-{forbidden}")},
                    )

        self.assertEqual(
            self.inventory.snapshot_content_hash,
            self.facts.snapshot_digest,
        )
        self.assertEqual(
            self.inventory.inventory_verification_receipt_digest,
            self.facts.inventory_verification_receipt_digest,
        )
        self.assertEqual(
            self.inventory.inventory_verifier_identity_digest,
            self.facts.inventory_verifier_identity_digest,
        )
        self.assertNotEqual(
            self.inventory.trust.freshness_receipt_digest,
            self.facts.inventory_verification_receipt_digest,
        )
        self.assertNotEqual(
            self.inventory.trust.context_digest,
            self.facts.inventory_verifier_identity_digest,
        )

        with self.assertRaises(DirectPathVerificationError) as raised:
            assess_inventory_closure_projection(
                self.fixture.authority,
                self.admission,
            )
        self.assertEqual(
            "CLOSURE_PROJECTION_INPUT_INVALID",
            raised.exception.code,
        )

    def test_projection_and_facts_digests_are_stable(self) -> None:
        inventory_again = self.fixture.verify()
        assessment_again = assess_inventory_closure_projection(
            inventory_again,
            self.admission,
        )
        facts_again = project_verified_closure_facts(
            inventory_again,
            self.admission,
        )

        self.assertEqual(
            self.assessment.assessment_digest,
            assessment_again.assessment_digest,
        )
        self.assertEqual(self.facts.facts_digest, facts_again.facts_digest)
        self.assertEqual(
            self.facts.hardware_semantic_digest,
            facts_again.hardware_semantic_digest,
        )

    def test_flat_dependency_actions_are_not_a_domain_kind_source(self) -> None:
        changed = InventoryFixture()
        typed_domains = copy.deepcopy(changed.records[0]["dependencyDomains"])
        changed.records[0]["dependencyActions"][0]["action"] = "LEASE_ONLY"
        changed.reseal()
        changed, changed_inventory, changed_admission = _typed_inputs(changed)
        changed_facts = project_verified_closure_facts(
            changed_inventory,
            changed_admission,
        )

        self.assertEqual(
            typed_domains,
            [domain.to_subject() for domain in changed_facts.devices[0].domains],
        )
        self.assertEqual(
            self.facts.hardware_semantic_digest,
            changed_facts.hardware_semantic_digest,
        )
        self.assertNotEqual(self.facts.facts_digest, changed_facts.facts_digest)

    def test_unknown_and_conflict_domains_map_exactly_then_fail_closed(
        self,
    ) -> None:
        for state in ("UNKNOWN", "CONFLICT"):
            with self.subTest(state=state):
                fixture = InventoryFixture()
                platform = next(
                    domain
                    for domain in fixture.records[0]["dependencyDomains"]
                    if domain["kind"] == "PLATFORM"
                )
                platform["state"] = state
                platform["edges"] = []
                fixture.reseal()
                fixture, inventory, admission = _typed_inputs(fixture)
                facts = project_verified_closure_facts(
                    inventory,
                    admission,
                )
                mapped = next(
                    domain
                    for domain in facts.devices[0].domains
                    if domain.kind is DependencyKind.PLATFORM
                )
                self.assertIs(FactState(state), mapped.state)
                self.assertEqual((), mapped.edges)

                result = resolve_dependency_closure(
                    facts=facts,
                    payload_device_uids=(fixture.records[0]["deviceUid"],),
                )
                self.assertFalse(result.success)
                self.assertIn(
                    "DEPENDENCY_PROVENANCE_UNKNOWN",
                    {reason.code for reason in result.reasons},
                )

    def test_known_typed_actions_reach_the_resolver(self) -> None:
        context = resolve_static_inventory_closure(
            self.inventory,
            self.admission,
        )
        result = context.result

        self.assertTrue(result.success)
        self.assertIs(self.inventory, context.inventory)
        self.assertIs(self.admission, context.admission)
        self.assertEqual(self.facts, context.facts)
        premise = context.hardware_premise
        self.assertEqual("YES", premise.hardware_gate.state.value)
        self.assertEqual("YES", premise.technical_gate.state.value)
        self.assertEqual(
            "COMPONENT_VERIFIED_INVENTORY_PREMISE_ONLY",
            premise.authority_boundary,
        )
        self.assertFalse(premise.product_authorized)
        self.assertEqual(
            self.fixture.records[0]["role"]["pciStructureFact"][
                "structureFactDigest"
            ],
            premise.device_premises[0]["pciStructureFactDigest"],
        )
        self.assertEqual(
            self.fixture.records[0]["resetContract"][
                "pciFlrCapabilityFact"
            ]["flrFactDigest"],
            premise.device_premises[0]["pciFlrCapabilityFactDigest"],
        )
        self.assertEqual(
            self.admission.closure_request,
            result.closure_request,
        )
        assert result.bundle is not None
        actions = {action.action for action in result.bundle.dependency_actions}
        self.assertEqual({DependencyAction.PAYLOAD}, actions)

    def test_payload_hardware_gate_cannot_be_invented_from_closure_action(
        self,
    ) -> None:
        fixture = InventoryFixture()
        fixture.records[0]["role"]["structuralRole"] = "FABRIC_DEPENDENCY"
        fixture.records[0]["resetContract"]["selectedMethodOrNull"] = (
            "VFIO_HOT_RESET"
        )
        fixture.reseal()
        fixture, inventory, admission = _typed_inputs(fixture)
        context = resolve_static_inventory_closure(inventory, admission)

        self.assertTrue(context.result.success)
        self.assertEqual(
            "NO",
            context.hardware_premise.hardware_gate.state.value,
        )
        self.assertIn(
            "HARDWARE_ROLE_NOT_ASSIGNABLE",
            {
                reason.code
                for reason in context.hardware_premise.hardware_gate.reasons
            },
        )
        self.assertFalse(context.hardware_premise.product_authorized)

    def test_owner_active_gate_covers_complete_closure_group(self) -> None:
        fixture = InventoryFixture()
        second_identity = copy.deepcopy(fixture.identity)
        second_identity["physicalPath"] = (
            "acpi:/_SB_/PCI0/RP05#adr=0000000000000001"
        )
        second = fixture.make_record(second_identity, "0000:01:00.1")
        fixture.records.append(second)
        first = fixture.records[0]
        second_uid = second["deviceUid"]
        provenance = digest("functional-owner-dependency")
        functional = next(
            domain
            for domain in first["dependencyDomains"]
            if domain["kind"] == "FUNCTIONAL"
        )
        functional["edges"] = [
            {
                "targetDeviceUid": second_uid,
                "actionState": "KNOWN",
                "requiredActionOrNull": "LEASE_ONLY",
                "provenanceDigest": provenance,
            }
        ]
        first["dependencyActions"].append(
            {
                "deviceUid": second_uid,
                "action": "LEASE_ONLY",
                "provenanceDigest": provenance,
            }
        )
        first["dependencyActions"].sort(
            key=lambda action: canonical_json_bytes(
                [action["deviceUid"], action["action"]]
            )
        )
        owner_group = sorted(
            (first["deviceUid"], second_uid),
            key=canonical_json_bytes,
        )
        first["owner"]["ownerActivationGroup"] = owner_group
        second["owner"]["ownerActivationGroup"] = owner_group
        second["owner"].update(
            {
                "hostActive": False,
                "effectiveOwner": "HOST",
                "activationDisposition": "REBOOT_REQUIRED",
                "driverOrNull": "host-driver",
            }
        )
        fixture.reseal()
        _, inventory, admission = _typed_inputs(fixture)
        context = resolve_static_inventory_closure(inventory, admission)

        self.assertTrue(context.result.success)
        self.assertEqual(
            tuple(owner_group),
            context.hardware_premise.owner_activation_device_uids,
        )
        self.assertEqual(
            "NO",
            context.hardware_premise.owner_active_gate.state.value,
        )
        self.assertIn(
            second_uid,
            {
                device
                for reason in context.hardware_premise.owner_active_gate.reasons
                for device in reason.devices
            },
        )

    def test_unknown_reset_fact_is_preserved_and_fails_closed(self) -> None:
        fixture = InventoryFixture()
        reset = fixture.records[0]["resetContract"]
        reset["state"] = "UNKNOWN"
        reset["supported"] = False
        reset["selectedMethodOrNull"] = None
        reset["resetAffectedSet"] = []
        fixture.reseal()
        fixture, inventory, admission = _typed_inputs(fixture)
        context = resolve_static_inventory_closure(inventory, admission)

        self.assertIs(
            FactState.UNKNOWN,
            context.facts.devices[0].reset_contract.state,
        )
        self.assertFalse(context.result.success)
        self.assertIn(
            "RESET_DOMAIN_UNVERIFIED",
            {reason.code for reason in context.result.reasons},
        )
        self.assertEqual(
            "NO",
            context.hardware_premise.hardware_gate.state.value,
        )

    def test_inventory_policy_age_and_pinned_snapshot_are_exact(self) -> None:
        with self.assertRaises(TypeError):
            replace(
                self.inventory,
                policy_hash=digest("caller-forged-policy"),
            )

        def internally_marked_inventory(**changes):
            values = {
                field.name: getattr(self.inventory, field.name)
                for field in fields(self.inventory)
            }
            values.update(changes)
            return type(self.inventory)._construct(**values)

        mutations = (
            (
                internally_marked_inventory(
                    policy_hash=digest("different-policy"),
                ),
                "STATIC_ADMISSION_INVENTORY_MISMATCH",
            ),
            (
                internally_marked_inventory(
                    verified_at=(self.inventory.captured_at + timedelta(seconds=61)),
                ),
                "HOST_SNAPSHOT_STALE",
            ),
            (
                internally_marked_inventory(
                    snapshot_content_hash=digest("different-current-snapshot"),
                ),
                "STATIC_ADMISSION_INVENTORY_MISMATCH",
            ),
        )
        for inventory, code in mutations:
            with self.subTest(code=code):
                with self.assertRaises(DirectPathVerificationError) as raised:
                    project_verified_closure_facts(
                        inventory,
                        self.admission,
                    )
                self.assertEqual(code, raised.exception.code)

    def test_static_bdf_drift_fails_before_closure(self) -> None:
        fixture = InventoryFixture()
        fixture, _inventory, admission = _typed_inputs(
            fixture,
            pinned=False,
        )
        record = fixture.records[0]
        retained_raw = bytes.fromhex(
            record["role"]["pciStructureFact"]["rawConfigSpaceHexOrNull"]
        )
        record["currentBdf"] = "0000:02:00.0"
        record["iommuProvider"]["kernelIommuGroup"] = ["0000:02:00.0"]
        fixture.bind_pci_capture(record, retained_raw)
        fixture.reseal()
        moved_inventory = fixture.verify()

        with self.assertRaises(DirectPathVerificationError) as raised:
            resolve_static_inventory_closure(
                moved_inventory,
                admission,
            )
        self.assertEqual(
            "STATIC_DEVICE_LOCATION_DRIFT",
            raised.exception.code,
        )
        self.assertTrue(raised.exception.path.endswith("expectedCurrentBdf"))

    def test_unverified_admission_object_is_not_an_escape_hatch(self) -> None:
        with self.assertRaises(DirectPathVerificationError) as raised:
            project_verified_closure_facts(
                self.inventory,
                self.admission.request,
            )
        self.assertEqual(
            "CLOSURE_PROJECTION_INPUT_INVALID",
            raised.exception.code,
        )
        self.assertEqual("admission", raised.exception.path)


if __name__ == "__main__":
    unittest.main()
