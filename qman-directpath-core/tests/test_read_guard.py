from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import timedelta
import inspect
from unittest.mock import patch
import unittest

from qman_directpath_core.authority import (
    AvailabilityMemberVersion,
    AvailabilityReadSet,
    CurrentAuthorityVector,
    RequestReadSet,
    ScopedCapabilityDependencies,
    assert_current,
    semantic_cache_reusable,
)
from qman_directpath_core.canonical import (
    canonical_json_bytes,
    sha256_digest,
)
from qman_directpath_core.capability import (
    AdmissionRequirement,
    CapabilityInput,
    EvaluationContext,
    GateAssessment,
    OperationContext,
    PolicyMode,
    Reason,
    ReasonDetail,
)
from qman_directpath_core.closure import (
    ClosureLimits,
    resolve_dependency_closure,
)
from qman_directpath_core.contracts import ContractSchemas
from qman_directpath_core.errors import DirectPathVerificationError
from qman_directpath_core.inventory_closure_factory import (
    VerifiedStaticInventoryClosureContext,
    resolve_static_inventory_closure,
)
from qman_directpath_core.qualification_profile import (
    bind_static_qualification_profile,
    verify_qualification_profile,
)
from qman_directpath_core.read_guard import (
    GuardedCapabilityRead,
    _validate_factory_capability_gates,
    evaluate_guarded_read,
)
from qman_directpath_core.resource_plan import (
    GUEST_RESOURCE_PLAN_CONTEXT_DOMAIN,
    GUEST_RESOURCE_PLAN_SCHEMA_DOCUMENT_REF,
    GUEST_RESOURCE_PLAN_SCHEMA_REF,
    MAX_GUEST_RESOURCE_PLAN_BYTES,
    MAX_ROOT_WINDOWS,
    VerifiedGuestResourcePlanContext,
    verify_guest_resource_plan,
)
from qman_directpath_core.static_capability import (
    VerifiedStaticCapabilityContext,
    bind_static_capability_context,
)
from qman_directpath_core.trust import (
    verify_qualification_context,
    verify_trust_context,
)
from tests.test_inventory import (
    CONTRACTS,
    NOW as INVENTORY_NOW,
    InventoryFixture,
)
from tests.test_inventory_closure_factory import _typed_inputs
from tests.test_host_snapshot_anchor import HostSnapshotAnchorFixture
from tests.test_qualification_profile import (
    PassingEvidenceVerifier,
    profile_documents_for,
)
from tests.test_trust import (
    NONCE,
    QualificationFixture,
    TrustFixture,
)


CHECKED_AT = INVENTORY_NOW


def digest(character: str) -> str:
    return "sha256:" + (character * 64)


def resource_plan_document(
    inventory_closure: VerifiedStaticInventoryClosureContext,
    qualification_binding,
):
    profile = qualification_binding.profile
    runtime = profile.qualification_record["kernelQemuFirmwareBackend"]
    plan = {
        "subjectType": "GUEST_RESOURCE_PLAN",
        "schemaVersion": 1,
        "planId": "plan-a",
        "runId": "run-a",
        "snapshotEpoch": inventory_closure.inventory.snapshot_epoch,
        "profileHash": profile.profile_hash,
        "guestAbiClass": profile.guest_abi_class,
        "machineType": runtime["machineType"],
        "firmwareKind": runtime["firmwareKind"],
        "rootWindows": [],
        "bridgeWindows": [],
        "barPlacements": [
            {
                "ownerId": (
                    inventory_closure.admission.request.payload_device_uids[0]
                ),
                "resourceClass": "MMIO64_PREFETCH",
                "base": 4_294_967_296,
                "size": 4096,
                "alignment": 4096,
            }
        ],
        "interruptPlanDigest": digest("1"),
        "rmrrPlanDigest": digest("2"),
        "qemuSettingsDigest": digest("3"),
        "allMandatoryResourcesAssigned": True,
        "planHash": None,
    }
    plan["planHash"] = sha256_digest(canonical_json_bytes(plan))
    return plan


def reseal_resource_plan(plan):
    plan["planHash"] = None
    plan["planHash"] = sha256_digest(canonical_json_bytes(plan))
    return plan


_SCHEMAS = ContractSchemas(CONTRACTS)
_TRUST_FIXTURE = TrustFixture(include_inventory_key=True)
_QUALIFICATION_FIXTURE = QualificationFixture(_TRUST_FIXTURE)
_STATIC_TRUST_CONTEXT = verify_trust_context(
    _SCHEMAS,
    pinned_root_set=_TRUST_FIXTURE.root,
    pinned_root_digest=_TRUST_FIXTURE.root["rootSetDigest"],
    key_ring_documents=[_TRUST_FIXTURE.ring],
    external_trust_anchor=_TRUST_FIXTURE.anchor,
    trust_anchor_freshness=_TRUST_FIXTURE.freshness,
    verifier_nonce=NONCE,
    now=CHECKED_AT,
)
_STATIC_QUALIFICATION_CONTEXT = verify_qualification_context(
    _SCHEMAS,
    _STATIC_TRUST_CONTEXT,
    catalog_documents=[_QUALIFICATION_FIXTURE.catalog],
    qualification_records=[_QUALIFICATION_FIXTURE.record],
    external_catalog_anchor=_QUALIFICATION_FIXTURE.anchor,
    catalog_anchor_freshness=_QUALIFICATION_FIXTURE.freshness,
    verifier_nonce=NONCE,
    now=CHECKED_AT,
)
_PROFILE_RECEIPT, _PROFILE_DOCUMENT = profile_documents_for(
    _SCHEMAS,
    _STATIC_QUALIFICATION_CONTEXT,
    _QUALIFICATION_FIXTURE,
)
STATIC_QUALIFICATION_PROFILE_CONTEXT = verify_qualification_profile(
    _SCHEMAS,
    _STATIC_QUALIFICATION_CONTEXT,
    qualification_record=_QUALIFICATION_FIXTURE.record,
    supported_catalog=_QUALIFICATION_FIXTURE.catalog,
    evidence_verifier=PassingEvidenceVerifier(),
    receipt_document=_PROFILE_RECEIPT,
    profile_document=_PROFILE_DOCUMENT,
)
if _TRUST_FIXTURE.inventory_private is None:
    raise AssertionError("unified fixture omitted its inventory key")
(
    _STATIC_FIXTURE,
    STATIC_INVENTORY_CONTEXT,
    STATIC_ADMISSION_CONTEXT,
) = _typed_inputs(
    fixture=InventoryFixture(
        private=_TRUST_FIXTURE.inventory_private,
        trust=_STATIC_TRUST_CONTEXT,
    ),
    profile=STATIC_QUALIFICATION_PROFILE_CONTEXT,
)
STATIC_INVENTORY_CLOSURE_CONTEXT = resolve_static_inventory_closure(
    STATIC_INVENTORY_CONTEXT,
    STATIC_ADMISSION_CONTEXT,
)
STATIC_QUALIFICATION_BINDING_CONTEXT = bind_static_qualification_profile(
    STATIC_ADMISSION_CONTEXT,
    STATIC_QUALIFICATION_PROFILE_CONTEXT,
)
STATIC_RESOURCE_PLAN_CONTEXT = verify_guest_resource_plan(
    _SCHEMAS,
    STATIC_INVENTORY_CLOSURE_CONTEXT,
    STATIC_QUALIFICATION_BINDING_CONTEXT,
    resource_plan_document(
        STATIC_INVENTORY_CLOSURE_CONTEXT,
        STATIC_QUALIFICATION_BINDING_CONTEXT,
    ),
)
STATIC_CAPABILITY_CONTEXT = bind_static_capability_context(
    STATIC_INVENTORY_CLOSURE_CONTEXT,
    STATIC_QUALIFICATION_BINDING_CONTEXT,
    STATIC_RESOURCE_PLAN_CONTEXT,
)
_HOST_SNAPSHOT_ANCHOR_FIXTURE = HostSnapshotAnchorFixture(
    genesis=False,
    schemas=_SCHEMAS,
    trust_fixture=_TRUST_FIXTURE,
    trust=_STATIC_TRUST_CONTEXT,
    inventory=STATIC_INVENTORY_CONTEXT,
)
HOST_SNAPSHOT_ANCHOR_BINDING = _HOST_SNAPSHOT_ANCHOR_FIXTURE.verify()
VALID_UNTIL = CHECKED_AT + timedelta(minutes=1)
EVIDENCE_VALID_UNTIL = min(
    STATIC_INVENTORY_CONTEXT.trust.freshness_expires_at,
    HOST_SNAPSHOT_ANCHOR_BINDING.freshness_expires_at,
    STATIC_ADMISSION_CONTEXT.policy.expires_at,
    STATIC_QUALIFICATION_PROFILE_CONTEXT.expires_at,
)


def closure_context():
    return (
        STATIC_INVENTORY_CLOSURE_CONTEXT.facts,
        STATIC_INVENTORY_CLOSURE_CONTEXT.result,
    )


def closure_arguments():
    return {
        "request_read_set": request_read_set(),
        "static_capability_context": STATIC_CAPABILITY_CONTEXT,
        "host_snapshot_anchor_binding": HOST_SNAPSHOT_ANCHOR_BINDING,
    }


def forged_inventory_closure_context(
    *,
    facts=None,
    result=None,
    hardware_premise=None,
) -> VerifiedStaticInventoryClosureContext:
    """Build an internally marked adversarial value for guard replay tests."""

    return VerifiedStaticInventoryClosureContext._construct(
        inventory=STATIC_INVENTORY_CONTEXT,
        admission=STATIC_ADMISSION_CONTEXT,
        facts=(STATIC_INVENTORY_CLOSURE_CONTEXT.facts if facts is None else facts),
        result=(STATIC_INVENTORY_CLOSURE_CONTEXT.result if result is None else result),
        hardware_premise=(
            STATIC_INVENTORY_CLOSURE_CONTEXT.hardware_premise
            if hardware_premise is None
            else hardware_premise
        ),
    )


def resource_plan_context_for(
    inventory_closure: VerifiedStaticInventoryClosureContext,
    qualification_binding=STATIC_QUALIFICATION_BINDING_CONTEXT,
) -> VerifiedGuestResourcePlanContext:
    return verify_guest_resource_plan(
        _SCHEMAS,
        inventory_closure,
        qualification_binding,
        resource_plan_document(
            inventory_closure,
            qualification_binding,
        ),
    )


def capability_context_for_inventory_closure(
    inventory_closure: VerifiedStaticInventoryClosureContext,
) -> VerifiedStaticCapabilityContext:
    """Build a marked adversarial composite for read-side replay tests."""

    premise = inventory_closure.hardware_premise
    return VerifiedStaticCapabilityContext._construct(
        inventory_closure=inventory_closure,
        qualification_binding=STATIC_QUALIFICATION_BINDING_CONTEXT,
        resource_plan=STATIC_RESOURCE_PLAN_CONTEXT,
        hardware_gate=premise.hardware_gate,
        technical_gate=premise.technical_gate,
        admin_gate=premise.admin_gate,
        owner_active_gate=premise.owner_active_gate,
        resource_plan_hash=STATIC_RESOURCE_PLAN_CONTEXT.plan_hash,
        hardware_premise_digest=premise.premise_digest,
        hardware_premise_authority_boundary=premise.authority_boundary,
        hardware_premise_product_authorized=premise.product_authorized,
        context_digest=STATIC_CAPABILITY_CONTEXT.context_digest,
    )


def availability_read_set(
    *,
    authority_resource_version: int = 19,
    member_device_uids: tuple[str, ...] | None = None,
    device_generation: int = 2,
    resource_version: int = 4,
    blocking_claim_digests: tuple[str, ...] = (),
    blocking_quarantine_record_digests: tuple[str, ...] = (),
) -> AvailabilityReadSet:
    _, closure = closure_context()
    assert closure.bundle is not None
    resolved_member_device_uids = (
        STATIC_ADMISSION_CONTEXT.request.payload_device_uids
        if member_device_uids is None
        else member_device_uids
    )
    members = tuple(
        AvailabilityMemberVersion(
            device_uid,
            device_generation,
            resource_version,
        )
        for device_uid in resolved_member_device_uids
    )
    unhashed = {
        "subjectType": "AVAILABILITY_READ_SET",
        "schemaVersion": 1,
        "authorityId": "qman-global-repository",
        "authorityResourceVersion": authority_resource_version,
        "bundleDigest": closure.bundle.bundle_hash,
        "memberVersions": [member.to_subject() for member in members],
        "blockingClaimDigests": list(blocking_claim_digests),
        "blockingQuarantineRecordDigests": list(blocking_quarantine_record_digests),
        "readSetDigest": None,
    }
    return AvailabilityReadSet(
        authority_id="qman-global-repository",
        authority_resource_version=authority_resource_version,
        bundle_digest=closure.bundle.bundle_hash,
        member_versions=members,
        blocking_claim_digests=blocking_claim_digests,
        blocking_quarantine_record_digests=(blocking_quarantine_record_digests),
        read_set_digest=sha256_digest(canonical_json_bytes(unhashed)),
    )


def request_read_set(
    *,
    request_version: int | None = None,
    request_resource_version: int | None = None,
    request_hash: str | None = None,
    request_entity_digest: str | None = None,
    authority_id: str = "qman-global-repository",
) -> RequestReadSet:
    request = STATIC_ADMISSION_CONTEXT.request
    resolved_request_version = (
        request.request_version if request_version is None else request_version
    )
    resolved_resource_version = (
        request.resource_version
        if request_resource_version is None
        else request_resource_version
    )
    resolved_request_hash = request_hash or request.request_hash
    resolved_entity_digest = request_entity_digest or request.entity_digest
    subject = {
        "subjectType": "REQUEST_READ_SET",
        "schemaVersion": 1,
        "authorityId": authority_id,
        "vmId": request.document["vmId"],
        "requestVersion": resolved_request_version,
        "requestResourceVersion": resolved_resource_version,
        "requestHash": resolved_request_hash,
        "requestEntityDigest": resolved_entity_digest,
        "readSetDigest": None,
    }
    return RequestReadSet(
        authority_id=authority_id,
        vm_id=request.document["vmId"],
        request_version=resolved_request_version,
        request_resource_version=resolved_resource_version,
        request_hash=resolved_request_hash,
        request_entity_digest=resolved_entity_digest,
        read_set_digest=sha256_digest(canonical_json_bytes(subject)),
    )


def dependencies() -> ScopedCapabilityDependencies:
    closure_facts, closure = closure_context()
    assert closure.bundle is not None and closure.reset_contract_set_digest is not None
    return ScopedCapabilityDependencies(
        publisher_snapshot_digest=(STATIC_INVENTORY_CONTEXT.snapshot_content_hash),
        hardware_snapshot_semantic_digest=(
            STATIC_INVENTORY_CONTEXT.snapshot_semantics.topology_digest
        ),
        policy_digest=STATIC_ADMISSION_CONTEXT.policy.policy_hash,
        qualification_profile_digest=(
            STATIC_QUALIFICATION_PROFILE_CONTEXT.profile_hash
        ),
        qualification_profile_semantic_digest=(
            STATIC_QUALIFICATION_PROFILE_CONTEXT.profile_semantic_digest
        ),
        qualification_record_digests=(
            STATIC_QUALIFICATION_PROFILE_CONTEXT.qualification_record_digests
        ),
        qualification_signer_key_ids=tuple(
            sorted(
                {
                    STATIC_QUALIFICATION_PROFILE_CONTEXT.dependency.qualification_signer_key_id,
                    _STATIC_QUALIFICATION_CONTEXT.product_release_signer_key_id,
                },
                key=canonical_json_bytes,
            )
        ),
        inventory_verifier_identity_digest=(
            STATIC_INVENTORY_CONTEXT.inventory_verifier_identity_digest
        ),
        dependency_bundle_digest=closure.bundle.bundle_hash,
        dependency_bundle_semantic_digest=closure.bundle.semantic_digest,
        reset_contract_digest=closure.reset_contract_set_digest,
        closure_request_digest=(closure.closure_request.request_digest),
        availability_read_set_digest=(availability_read_set().read_set_digest),
        request_read_set_digest=request_read_set().read_set_digest,
        request_digest=STATIC_ADMISSION_CONTEXT.request.request_hash,
    )


def authority() -> CurrentAuthorityVector:
    trust = STATIC_INVENTORY_CONTEXT.trust
    return CurrentAuthorityVector(
        host_authority_id=STATIC_INVENTORY_CONTEXT.host_id,
        host_authority_resource_version=(
            STATIC_INVENTORY_CONTEXT.observed_authority_resource_version
        ),
        publisher_snapshot_digest=(STATIC_INVENTORY_CONTEXT.snapshot_content_hash),
        host_snapshot_anchor_authority_id=(
            HOST_SNAPSHOT_ANCHOR_BINDING.anchor_authority_id
        ),
        host_snapshot_anchor_version=(
            HOST_SNAPSHOT_ANCHOR_BINDING.anchor_version
        ),
        host_snapshot_anchor_resource_version=(
            HOST_SNAPSHOT_ANCHOR_BINDING.anchor_resource_version
        ),
        host_snapshot_anchor_digest=(
            HOST_SNAPSHOT_ANCHOR_BINDING.anchor_digest
        ),
        host_snapshot_anchor_freshness_receipt_digest=(
            HOST_SNAPSHOT_ANCHOR_BINDING.freshness_receipt_digest
        ),
        host_snapshot_anchor_binding_digest=(
            HOST_SNAPSHOT_ANCHOR_BINDING.binding_digest
        ),
        policy_authority_id="qman-policy-authority",
        policy_id=STATIC_ADMISSION_CONTEXT.policy.policy_id,
        policy_version=STATIC_ADMISSION_CONTEXT.policy.policy_version,
        policy_digest=STATIC_ADMISSION_CONTEXT.policy.policy_hash,
        policy_authority_resource_version=11,
        trust_root_digest=trust.root_set_digest,
        key_ring_sequence=trust.key_ring_sequence,
        key_ring_digest=trust.key_ring_digest,
        trust_anchor_version=trust.trust_anchor_version,
        trust_anchor_digest=trust.trust_anchor_digest,
        catalog_id=_STATIC_QUALIFICATION_CONTEXT.catalog_id,
        catalog_sequence=(_STATIC_QUALIFICATION_CONTEXT.catalog_sequence),
        catalog_digest=_STATIC_QUALIFICATION_CONTEXT.catalog_digest,
        catalog_anchor_version=(_STATIC_QUALIFICATION_CONTEXT.catalog_anchor_version),
        catalog_anchor_digest=(_STATIC_QUALIFICATION_CONTEXT.catalog_anchor_digest),
        availability_authority_id="qman-global-repository",
        availability_authority_resource_version=19,
        availability_read_set_digest=(availability_read_set().read_set_digest),
        request_authority_id="qman-global-repository",
        request_read_set_digest=request_read_set().read_set_digest,
        inventory_verification_receipt_digest=(
            STATIC_INVENTORY_CONTEXT.inventory_verification_receipt_digest
        ),
        inventory_verifier_identity_digest=(
            STATIC_INVENTORY_CONTEXT.inventory_verifier_identity_digest
        ),
        evidence_valid_until=EVIDENCE_VALID_UNTIL,
    )


def capability_input() -> CapabilityInput:
    closure_facts, closure = closure_context()
    yes = GateAssessment.yes()
    return CapabilityInput(
        evaluation_context=EvaluationContext.VM_REQUEST,
        operation_context=OperationContext.STATIC_ADMISSION,
        policy_mode=PolicyMode.PRODUCTION,
        admission_requirement=AdmissionRequirement.SUPPORTED,
        request_hash=STATIC_ADMISSION_CONTEXT.request.request_hash,
        closure_request_hash=closure.closure_request.request_digest,
        snapshot_epoch=STATIC_INVENTORY_CONTEXT.snapshot_epoch,
        snapshot_semantic_hash=(
            STATIC_INVENTORY_CONTEXT.snapshot_semantics.topology_digest
        ),
        policy_hash=STATIC_ADMISSION_CONTEXT.policy.policy_hash,
        profile_hash=STATIC_QUALIFICATION_PROFILE_CONTEXT.profile_hash,
        profile_semantic_hash=(
            STATIC_QUALIFICATION_PROFILE_CONTEXT.profile_semantic_digest
        ),
        bundle=closure.dependency_bundle_reference(),
        reset_contract=closure.reset_contract_reference(),
        resource_plan_hash=STATIC_CAPABILITY_CONTEXT.resource_plan_hash,
        hardware=STATIC_CAPABILITY_CONTEXT.hardware_gate,
        technical=STATIC_CAPABILITY_CONTEXT.technical_gate,
        qualification=yes,
        catalog_support=yes,
        policy_gate=yes,
        lab_policy_gate=None,
        admin_gate=STATIC_CAPABILITY_CONTEXT.admin_gate,
        owner_active_gate=STATIC_CAPABILITY_CONTEXT.owner_active_gate,
        availability_gate=yes,
        current_request_gate=yes,
    )


class ReadGuardTests(unittest.TestCase):
    def test_verified_pipeline_values_are_factory_only(self) -> None:
        trust = STATIC_INVENTORY_CONTEXT.trust
        record = STATIC_INVENTORY_CONTEXT.device_records[0]
        values = (
            STATIC_ADMISSION_CONTEXT.request,
            STATIC_ADMISSION_CONTEXT.policy,
            STATIC_ADMISSION_CONTEXT,
            next(iter(trust.keys.values())),
            trust._rings[-1],
            trust,
            record.identity,
            record,
            STATIC_INVENTORY_CONTEXT.verifier_algorithm_identity,
            STATIC_INVENTORY_CONTEXT,
            STATIC_INVENTORY_CLOSURE_CONTEXT,
            STATIC_QUALIFICATION_PROFILE_CONTEXT,
            STATIC_QUALIFICATION_BINDING_CONTEXT,
            STATIC_RESOURCE_PLAN_CONTEXT,
            STATIC_CAPABILITY_CONTEXT,
            HOST_SNAPSHOT_ANCHOR_BINDING,
        )
        for value in values:
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(TypeError):
                    type(value)()
                with self.assertRaises(TypeError):
                    replace(value)

    def test_static_capability_factory_is_exact_and_rejects_mixing(
        self,
    ) -> None:
        replayed = bind_static_capability_context(
            STATIC_INVENTORY_CLOSURE_CONTEXT,
            STATIC_QUALIFICATION_BINDING_CONTEXT,
            STATIC_RESOURCE_PLAN_CONTEXT,
        )
        self.assertEqual(STATIC_CAPABILITY_CONTEXT, replayed)
        self.assertEqual(
            STATIC_CAPABILITY_CONTEXT.context_digest,
            sha256_digest(
                canonical_json_bytes(
                    {
                        **STATIC_CAPABILITY_CONTEXT.to_subject(),
                        "contextDigest": None,
                    }
                )
            ),
        )
        self.assertEqual(
            {
                "qualificationVerificationDisposition": "STRUCTURALLY_VALID",
                "qualificationAuthorityBoundary": "COMPONENT_ONLY",
                "qualificationComponentAuthority": False,
                "qualificationProductAuthorized": False,
                "qualificationAuthorizationBlockers": [
                    "TRUSTED_E4_ADAPTER_REQUIRED",
                ],
            },
            {
                key: STATIC_CAPABILITY_CONTEXT.to_subject()[key]
                for key in (
                    "qualificationVerificationDisposition",
                    "qualificationAuthorityBoundary",
                    "qualificationComponentAuthority",
                    "qualificationProductAuthorized",
                    "qualificationAuthorizationBlockers",
                )
            },
        )
        with self.assertRaises(TypeError):
            VerifiedStaticCapabilityContext()
        with self.assertRaises(TypeError):
            replace(STATIC_CAPABILITY_CONTEXT)

        _, other_inventory, other_admission = _typed_inputs(
            pinned=False,
            profile=STATIC_QUALIFICATION_PROFILE_CONTEXT,
        )
        other_inventory_closure = resolve_static_inventory_closure(
            other_inventory,
            other_admission,
        )
        other_qualification = bind_static_qualification_profile(
            other_admission,
            STATIC_QUALIFICATION_PROFILE_CONTEXT,
        )
        for inventory_closure, qualification_binding in (
            (
                other_inventory_closure,
                STATIC_QUALIFICATION_BINDING_CONTEXT,
            ),
            (
                STATIC_INVENTORY_CLOSURE_CONTEXT,
                other_qualification,
            ),
        ):
            with self.subTest(admission=inventory_closure.admission.context_digest):
                with self.assertRaises(DirectPathVerificationError) as raised:
                    bind_static_capability_context(
                        inventory_closure,
                        qualification_binding,
                        STATIC_RESOURCE_PLAN_CONTEXT,
                    )
                self.assertEqual(
                    "STATIC_CAPABILITY_ADMISSION_MISMATCH",
                    raised.exception.code,
                )

    def test_resource_plan_context_is_closed_replayed_and_factory_only(
        self,
    ) -> None:
        replayed = verify_guest_resource_plan(
            _SCHEMAS,
            STATIC_INVENTORY_CLOSURE_CONTEXT,
            STATIC_QUALIFICATION_BINDING_CONTEXT,
            STATIC_RESOURCE_PLAN_CONTEXT.canonical_bytes,
        )
        self.assertEqual(STATIC_RESOURCE_PLAN_CONTEXT, replayed)
        self.assertEqual(
            STATIC_RESOURCE_PLAN_CONTEXT.context_digest,
            sha256_digest(
                GUEST_RESOURCE_PLAN_CONTEXT_DOMAIN
                + canonical_json_bytes(
                    {
                        **STATIC_RESOURCE_PLAN_CONTEXT.to_subject(),
                        "contextDigest": None,
                    }
                )
            ),
        )
        self.assertFalse(
            STATIC_RESOURCE_PLAN_CONTEXT.product_authorized,
        )
        self.assertEqual(
            _SCHEMAS.digest_for_ref(
                GUEST_RESOURCE_PLAN_SCHEMA_DOCUMENT_REF,
                path="test.resourcePlan.schemaRef",
            ),
            STATIC_RESOURCE_PLAN_CONTEXT.schema_digest,
        )
        self.assertEqual(
            GUEST_RESOURCE_PLAN_SCHEMA_REF,
            STATIC_RESOURCE_PLAN_CONTEXT.schema_ref,
        )
        with self.assertRaises(TypeError):
            VerifiedGuestResourcePlanContext()
        with self.assertRaises(TypeError):
            replace(STATIC_RESOURCE_PLAN_CONTEXT)

    def test_resource_plan_hash_and_bindings_are_not_labels(self) -> None:
        baseline = resource_plan_document(
            STATIC_INVENTORY_CLOSURE_CONTEXT,
            STATIC_QUALIFICATION_BINDING_CONTEXT,
        )
        cases = (
            (
                "planHash",
                {**baseline, "planHash": digest("0")},
                "RESOURCE_PLAN_HASH_INVALID",
            ),
            (
                "snapshotEpoch",
                reseal_resource_plan(
                    {**baseline, "snapshotEpoch": baseline["snapshotEpoch"] + 1}
                ),
                "RESOURCE_PLAN_BINDING_MISMATCH",
            ),
            (
                "profileHash",
                reseal_resource_plan(
                    {**baseline, "profileHash": digest("0")}
                ),
                "RESOURCE_PLAN_BINDING_MISMATCH",
            ),
            (
                "guestAbiClass",
                reseal_resource_plan(
                    {**baseline, "guestAbiClass": "forged-abi"}
                ),
                "RESOURCE_PLAN_BINDING_MISMATCH",
            ),
        )
        for name, plan, expected_code in cases:
            with self.subTest(name=name):
                with self.assertRaises(
                    DirectPathVerificationError
                ) as raised:
                    verify_guest_resource_plan(
                        _SCHEMAS,
                        STATIC_INVENTORY_CLOSURE_CONTEXT,
                        STATIC_QUALIFICATION_BINDING_CONTEXT,
                        plan,
                    )
                self.assertEqual(expected_code, raised.exception.code)

    def test_resource_plan_window_arithmetic_is_replayed(self) -> None:
        plan = resource_plan_document(
            STATIC_INVENTORY_CLOSURE_CONTEXT,
            STATIC_QUALIFICATION_BINDING_CONTEXT,
        )
        plan["barPlacements"][0]["base"] += 1
        reseal_resource_plan(plan)
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_guest_resource_plan(
                _SCHEMAS,
                STATIC_INVENTORY_CLOSURE_CONTEXT,
                STATIC_QUALIFICATION_BINDING_CONTEXT,
                plan,
            )
        self.assertEqual("RESOURCE_PLAN_INVALID", raised.exception.code)
        self.assertEqual(
            "resourcePlan.barPlacements[0]",
            raised.exception.path,
        )

    def test_resource_plan_budgets_fail_closed_before_validation(self) -> None:
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_guest_resource_plan(
                _SCHEMAS,
                STATIC_INVENTORY_CLOSURE_CONTEXT,
                STATIC_QUALIFICATION_BINDING_CONTEXT,
                b" " * (MAX_GUEST_RESOURCE_PLAN_BYTES + 1),
            )
        self.assertEqual("RESOURCE_PLAN_TOO_LARGE", raised.exception.code)

        plan = resource_plan_document(
            STATIC_INVENTORY_CLOSURE_CONTEXT,
            STATIC_QUALIFICATION_BINDING_CONTEXT,
        )
        plan["rootWindows"] = [
            {
                "ownerId": f"root-{index}",
                "resourceClass": "MMIO32",
                "base": index * 4096,
                "size": 4096,
                "alignment": 4096,
            }
            for index in range(MAX_ROOT_WINDOWS + 1)
        ]
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_guest_resource_plan(
                _SCHEMAS,
                STATIC_INVENTORY_CLOSURE_CONTEXT,
                STATIC_QUALIFICATION_BINDING_CONTEXT,
                plan,
            )
        self.assertEqual("RESOURCE_PLAN_TOO_LARGE", raised.exception.code)
        self.assertEqual("resourcePlan.rootWindows", raised.exception.path)

    def test_three_identical_reads_are_byte_stable(self) -> None:
        results = tuple(
            evaluate_guarded_read(
                before_current_vector=authority(),
                capability_input=capability_input(),
                dependencies=dependencies(),
                after_current_vector=authority(),
                availability_read_set=availability_read_set(),
                **closure_arguments(),
                checked_at=CHECKED_AT,
                valid_until=VALID_UNTIL,
            )
            for _ in range(3)
        )

        self.assertEqual(results[0], results[1])
        self.assertEqual(results[1], results[2])
        self.assertEqual(
            results[0].evaluation.to_wire(),
            results[2].evaluation.to_wire(),
        )
        self.assertEqual(
            results[0].authorization.authority_vector_digest,
            authority().vector_digest,
        )

    def test_catalog_ring_or_host_pointer_advance_rejects_response(self) -> None:
        advances = (
            {
                "host_authority_resource_version": 10,
            },
            {
                "host_snapshot_anchor_version": (
                    authority().host_snapshot_anchor_version + 1
                ),
                "host_snapshot_anchor_resource_version": (
                    authority().host_snapshot_anchor_resource_version + 1
                ),
                "host_snapshot_anchor_digest": digest("a"),
                "host_snapshot_anchor_freshness_receipt_digest": digest(
                    "b"
                ),
                "host_snapshot_anchor_binding_digest": digest("c"),
            },
            {
                "key_ring_sequence": 5,
                "key_ring_digest": digest("0"),
            },
            {
                "catalog_sequence": 8,
                "catalog_digest": digest("0"),
                "catalog_anchor_version": 8,
                "catalog_anchor_digest": digest("0"),
                "inventory_verification_receipt_digest": digest("0"),
            },
        )
        for advance in advances:
            with self.subTest(advance=advance):
                with self.assertRaises(DirectPathVerificationError) as raised:
                    evaluate_guarded_read(
                        before_current_vector=authority(),
                        capability_input=capability_input(),
                        dependencies=dependencies(),
                        after_current_vector=replace(authority(), **advance),
                        availability_read_set=availability_read_set(),
                        **closure_arguments(),
                        checked_at=CHECKED_AT,
                        valid_until=VALID_UNTIL,
                    )
                self.assertEqual(raised.exception.code, "STALE_AUTHORITY")

    def test_before_vector_must_identify_exact_verified_inventory(self) -> None:
        mutations = (
            (
                {"host_authority_id": "another-host"},
                "before_current_vector.host_authority_id",
            ),
            (
                {
                    "host_authority_resource_version": (
                        authority().host_authority_resource_version + 1
                    )
                },
                "before_current_vector.host_authority_resource_version",
            ),
            (
                {"trust_root_digest": digest("0")},
                "before_current_vector.trust_root_digest",
            ),
            (
                {
                    "host_snapshot_anchor_authority_id": (
                        "other-host-snapshot-authority"
                    )
                },
                "before_current_vector.host_snapshot_anchor_authority_id",
            ),
            (
                {
                    "host_snapshot_anchor_version": (
                        authority().host_snapshot_anchor_version + 1
                    )
                },
                "before_current_vector.host_snapshot_anchor_version",
            ),
            (
                {
                    "host_snapshot_anchor_resource_version": (
                        authority().host_snapshot_anchor_resource_version + 1
                    )
                },
                "before_current_vector."
                "host_snapshot_anchor_resource_version",
            ),
            (
                {"host_snapshot_anchor_digest": digest("2")},
                "before_current_vector.host_snapshot_anchor_digest",
            ),
            (
                {
                    "host_snapshot_anchor_freshness_receipt_digest": (
                        digest("3")
                    )
                },
                "before_current_vector."
                "host_snapshot_anchor_freshness_receipt_digest",
            ),
            (
                {"host_snapshot_anchor_binding_digest": digest("4")},
                "before_current_vector.host_snapshot_anchor_binding_digest",
            ),
            (
                {
                    "key_ring_sequence": (authority().key_ring_sequence + 1),
                    "key_ring_digest": digest("1"),
                },
                "before_current_vector.key_ring_sequence",
            ),
        )
        for changes, expected_path in mutations:
            with self.subTest(changes=changes):
                changed = replace(authority(), **changes)
                with self.assertRaises(DirectPathVerificationError) as raised:
                    evaluate_guarded_read(
                        before_current_vector=changed,
                        capability_input=capability_input(),
                        dependencies=dependencies(),
                        after_current_vector=changed,
                        availability_read_set=availability_read_set(),
                        **closure_arguments(),
                        checked_at=CHECKED_AT,
                        valid_until=VALID_UNTIL,
                    )
                self.assertEqual(
                    "STALE_AUTHORITY",
                    raised.exception.code,
                )
                self.assertEqual(expected_path, raised.exception.path)

    def test_host_snapshot_anchor_binding_is_factory_exact_and_live(
        self,
    ) -> None:
        arguments = closure_arguments()
        arguments["host_snapshot_anchor_binding"] = object()
        with (
            patch(
                "qman_directpath_core.read_guard.evaluate_capability",
                side_effect=AssertionError("capability evaluation reached"),
            ),
            self.assertRaises(DirectPathVerificationError) as raised,
        ):
            evaluate_guarded_read(
                before_current_vector=authority(),
                capability_input=capability_input(),
                dependencies=dependencies(),
                after_current_vector=authority(),
                availability_read_set=availability_read_set(),
                **arguments,
                checked_at=CHECKED_AT,
                valid_until=VALID_UNTIL,
            )
        self.assertEqual("EVIDENCE_INCOMPLETE", raised.exception.code)
        self.assertEqual(
            "host_snapshot_anchor_binding",
            raised.exception.path,
        )

        for checked_at, valid_until, expected_path in (
            (
                HOST_SNAPSHOT_ANCHOR_BINDING.freshness_expires_at,
                HOST_SNAPSHOT_ANCHOR_BINDING.freshness_expires_at,
                "checked_at",
            ),
            (
                CHECKED_AT,
                HOST_SNAPSHOT_ANCHOR_BINDING.freshness_expires_at
                + timedelta(microseconds=1),
                "valid_until",
            ),
        ):
            with (
                self.subTest(expected_path=expected_path),
                patch(
                    "qman_directpath_core.read_guard.evaluate_capability",
                    side_effect=AssertionError(
                        "capability evaluation reached"
                    ),
                ),
                self.assertRaises(DirectPathVerificationError) as raised,
            ):
                evaluate_guarded_read(
                    before_current_vector=authority(),
                    capability_input=capability_input(),
                    dependencies=dependencies(),
                    after_current_vector=authority(),
                    availability_read_set=availability_read_set(),
                    **closure_arguments(),
                    checked_at=checked_at,
                    valid_until=valid_until,
                )
            self.assertEqual("STALE_AUTHORITY", raised.exception.code)
            self.assertEqual(expected_path, raised.exception.path)

    def test_valid_anchor_for_another_inventory_is_rejected(self) -> None:
        other_binding = HostSnapshotAnchorFixture().verify()
        arguments = closure_arguments()
        arguments["host_snapshot_anchor_binding"] = other_binding

        with self.assertRaises(DirectPathVerificationError) as raised:
            evaluate_guarded_read(
                before_current_vector=authority(),
                capability_input=capability_input(),
                dependencies=dependencies(),
                after_current_vector=authority(),
                availability_read_set=availability_read_set(),
                **arguments,
                checked_at=CHECKED_AT,
                valid_until=VALID_UNTIL,
            )
        self.assertEqual("STALE_AUTHORITY", raised.exception.code)
        self.assertEqual(
            "host_snapshot_anchor_binding.trust",
            raised.exception.path,
        )

    def test_every_selected_binding_is_checked_before_evaluation(self) -> None:
        source = capability_input()
        mismatches = (
            replace(source, request_hash=digest("0")),
            replace(source, closure_request_hash=digest("0")),
            replace(source, policy_hash=digest("0")),
            replace(source, profile_hash=digest("0")),
            replace(source, profile_semantic_hash=digest("f")),
            replace(source, snapshot_semantic_hash=digest("f")),
            replace(
                source,
                bundle=replace(source.bundle, content_hash=digest("0")),
            ),
            replace(
                source,
                reset_contract=replace(
                    source.reset_contract,
                    content_hash=digest("0"),
                ),
            ),
        )
        for mismatch in mismatches:
            with self.subTest(mismatch=mismatch):
                with self.assertRaises(DirectPathVerificationError) as raised:
                    evaluate_guarded_read(
                        before_current_vector=authority(),
                        capability_input=mismatch,
                        dependencies=dependencies(),
                        after_current_vector=authority(),
                        availability_read_set=availability_read_set(),
                        **closure_arguments(),
                        checked_at=CHECKED_AT,
                        valid_until=VALID_UNTIL,
                    )
                self.assertEqual(raised.exception.code, "STALE_AUTHORITY")

        with self.assertRaises(DirectPathVerificationError) as raised:
            evaluate_guarded_read(
                before_current_vector=authority(),
                capability_input=source,
                dependencies=replace(
                    dependencies(),
                    inventory_verifier_identity_digest=digest("0"),
                ),
                after_current_vector=authority(),
                availability_read_set=availability_read_set(),
                **closure_arguments(),
                checked_at=CHECKED_AT,
                valid_until=VALID_UNTIL,
            )
        self.assertEqual(raised.exception.code, "STALE_AUTHORITY")

    def test_verified_profile_dependency_and_signer_drift_is_rejected(
        self,
    ) -> None:
        mutations = (
            (
                {
                    "qualification_profile_digest": digest("0"),
                },
                "dependencies.qualification_profile_digest",
            ),
            (
                {
                    "qualification_profile_semantic_digest": digest("1"),
                },
                "dependencies.qualification_profile_semantic_digest",
            ),
            (
                {
                    "qualification_record_digests": (digest("2"),),
                },
                "dependencies.qualification_record_digests",
            ),
            (
                {
                    "qualification_signer_key_ids": ("forged-key",),
                },
                "dependencies.qualification_signer_key_ids",
            ),
        )
        for changes, expected_path in mutations:
            with self.subTest(expected_path=expected_path):
                with self.assertRaises(DirectPathVerificationError) as raised:
                    evaluate_guarded_read(
                        before_current_vector=authority(),
                        capability_input=capability_input(),
                        dependencies=replace(
                            dependencies(),
                            **changes,
                        ),
                        after_current_vector=authority(),
                        availability_read_set=availability_read_set(),
                        **closure_arguments(),
                        checked_at=CHECKED_AT,
                        valid_until=VALID_UNTIL,
                    )
                self.assertEqual("STALE_AUTHORITY", raised.exception.code)
                self.assertEqual(expected_path, raised.exception.path)

    def test_policy_catalog_and_trust_current_tuple_is_exact(self) -> None:
        mutations = (
            (
                {"policy_id": "another-policy"},
                "before_current_vector.policy_id",
            ),
            (
                {
                    "policy_version": (
                        STATIC_ADMISSION_CONTEXT.policy.policy_version + 1
                    )
                },
                "before_current_vector.policy_version",
            ),
            (
                {"catalog_id": "another-catalog"},
                "before_current_vector.catalog_id",
            ),
            (
                {
                    "catalog_sequence": (
                        _STATIC_QUALIFICATION_CONTEXT.catalog_sequence + 1
                    )
                },
                "before_current_vector.catalog_sequence",
            ),
            (
                {"catalog_digest": digest("3")},
                "before_current_vector.catalog_digest",
            ),
            (
                {
                    "catalog_anchor_version": (
                        _STATIC_QUALIFICATION_CONTEXT.catalog_anchor_version + 1
                    )
                },
                "before_current_vector.catalog_anchor_version",
            ),
            (
                {"catalog_anchor_digest": digest("4")},
                "before_current_vector.catalog_anchor_digest",
            ),
            (
                {
                    "trust_anchor_version": (
                        _STATIC_TRUST_CONTEXT.trust_anchor_version + 1
                    )
                },
                "before_current_vector.trust_anchor_version",
            ),
            (
                {"trust_anchor_digest": digest("5")},
                "before_current_vector.trust_anchor_digest",
            ),
            (
                {
                    "evidence_valid_until": (
                        EVIDENCE_VALID_UNTIL + timedelta(microseconds=1)
                    )
                },
                "before_current_vector.evidence_valid_until",
            ),
        )
        for changes, expected_path in mutations:
            with self.subTest(expected_path=expected_path):
                changed = replace(authority(), **changes)
                with self.assertRaises(DirectPathVerificationError) as raised:
                    evaluate_guarded_read(
                        before_current_vector=changed,
                        capability_input=capability_input(),
                        dependencies=dependencies(),
                        after_current_vector=changed,
                        availability_read_set=availability_read_set(),
                        **closure_arguments(),
                        checked_at=CHECKED_AT,
                        valid_until=VALID_UNTIL,
                    )
                self.assertEqual("STALE_AUTHORITY", raised.exception.code)
                self.assertEqual(expected_path, raised.exception.path)

    def test_current_request_row_must_exactly_match_verified_context(
        self,
    ) -> None:
        changes = (
            (
                request_read_set(request_version=2),
                "request_read_set.request_version",
            ),
            (
                request_read_set(request_resource_version=20),
                "request_read_set.request_resource_version",
            ),
            (
                request_read_set(request_hash=digest("0")),
                "request_read_set.request_hash",
            ),
            (
                request_read_set(request_entity_digest=digest("0")),
                "request_read_set.request_entity_digest",
            ),
        )
        for stale_read_set, expected_path in changes:
            with self.subTest(expected_path=expected_path):
                selected = replace(
                    dependencies(),
                    request_read_set_digest=(stale_read_set.read_set_digest),
                )
                current = replace(
                    authority(),
                    request_read_set_digest=(stale_read_set.read_set_digest),
                )
                arguments = closure_arguments()
                arguments["request_read_set"] = stale_read_set
                with (
                    patch(
                        "qman_directpath_core.read_guard.evaluate_capability",
                        side_effect=AssertionError(
                            "capability evaluated before request binding"
                        ),
                    ),
                    self.assertRaises(DirectPathVerificationError) as raised,
                ):
                    evaluate_guarded_read(
                        before_current_vector=current,
                        capability_input=capability_input(),
                        dependencies=selected,
                        after_current_vector=current,
                        availability_read_set=availability_read_set(),
                        **arguments,
                        checked_at=CHECKED_AT,
                        valid_until=VALID_UNTIL,
                    )
                self.assertEqual("STALE_AUTHORITY", raised.exception.code)
                self.assertEqual(expected_path, raised.exception.path)

    def test_request_vector_drift_invalidates_old_authorization(self) -> None:
        initial = evaluate_guarded_read(
            before_current_vector=authority(),
            capability_input=capability_input(),
            dependencies=dependencies(),
            after_current_vector=authority(),
            availability_read_set=availability_read_set(),
            **closure_arguments(),
            checked_at=CHECKED_AT,
            valid_until=VALID_UNTIL,
        )
        advanced_read_set = request_read_set(
            request_resource_version=20,
        )
        advanced_current = replace(
            authority(),
            request_read_set_digest=advanced_read_set.read_set_digest,
        )

        self.assertTrue(
            semantic_cache_reusable(
                initial.authorization,
                replace(
                    dependencies(),
                    request_read_set_digest=(advanced_read_set.read_set_digest),
                ),
            )
        )
        with self.assertRaises(DirectPathVerificationError) as raised:
            assert_current(
                initial.authorization,
                advanced_current,
                at=CHECKED_AT,
                expected_decision_digest=(initial.evaluation.decision.decision_hash),
                dependencies=dependencies(),
            )
        self.assertEqual("STALE_AUTHORITY", raised.exception.code)

    def test_wrong_static_context_and_non_vm_input_fail_closed(self) -> None:
        with self.assertRaises(TypeError):
            replace(
                STATIC_ADMISSION_CONTEXT.request,
                resource_version=20,
            )
        arguments = closure_arguments()
        arguments["static_capability_context"] = object()
        with self.assertRaises(DirectPathVerificationError) as raised:
            evaluate_guarded_read(
                before_current_vector=authority(),
                capability_input=capability_input(),
                dependencies=dependencies(),
                after_current_vector=authority(),
                availability_read_set=availability_read_set(),
                **arguments,
                checked_at=CHECKED_AT,
                valid_until=VALID_UNTIL,
            )
        self.assertEqual("EVIDENCE_INCOMPLETE", raised.exception.code)
        self.assertEqual(
            "static_capability_context",
            raised.exception.path,
        )

        host_input = replace(
            capability_input(),
            evaluation_context=EvaluationContext.HOST_ONLY,
            technical=None,
            resource_plan_hash=None,
            current_request_gate=None,
        )
        with self.assertRaises(DirectPathVerificationError) as raised:
            evaluate_guarded_read(
                before_current_vector=authority(),
                capability_input=host_input,
                dependencies=dependencies(),
                after_current_vector=authority(),
                availability_read_set=availability_read_set(),
                **closure_arguments(),
                checked_at=CHECKED_AT,
                valid_until=VALID_UNTIL,
            )
        self.assertEqual(
            "CAPABILITY_INPUT_INVALID",
            raised.exception.code,
        )

    def test_caller_cannot_self_report_hardware_yes_over_factory_no(
        self,
    ) -> None:
        fixture = InventoryFixture(
            private=_TRUST_FIXTURE.inventory_private,
            trust=_STATIC_TRUST_CONTEXT,
        )
        fixture.records[0]["role"]["structuralRole"] = "FABRIC_DEPENDENCY"
        fixture.records[0]["resetContract"]["selectedMethodOrNull"] = (
            "VFIO_HOT_RESET"
        )
        fixture.reseal()
        _, inventory, admission = _typed_inputs(
            fixture=fixture,
            profile=STATIC_QUALIFICATION_PROFILE_CONTEXT,
        )
        inventory_closure = resolve_static_inventory_closure(
            inventory,
            admission,
        )
        qualification_binding = bind_static_qualification_profile(
            admission,
            STATIC_QUALIFICATION_PROFILE_CONTEXT,
        )
        static_context = bind_static_capability_context(
            inventory_closure,
            qualification_binding,
            resource_plan_context_for(
                inventory_closure,
                qualification_binding,
            ),
        )
        self.assertEqual("NO", static_context.hardware_gate.state.value)
        self.assertFalse(static_context.hardware_premise_product_authorized)

        caller_claim = replace(
            capability_input(),
            hardware=GateAssessment.yes(),
            technical=GateAssessment.yes(),
        )
        with self.assertRaises(DirectPathVerificationError) as raised:
            _validate_factory_capability_gates(
                caller_claim,
                static_context,
            )
        self.assertEqual("EVIDENCE_INCOMPLETE", raised.exception.code)
        self.assertEqual("capability_input.hardware", raised.exception.path)

    def test_caller_cannot_self_report_admin_yes_over_factory_no(
        self,
    ) -> None:
        fixture = InventoryFixture(
            private=_TRUST_FIXTURE.inventory_private,
            trust=_STATIC_TRUST_CONTEXT,
        )
        fixture.records[0]["owner"].update(
            {
                "adminEnabled": False,
                "hostActive": False,
                "effectiveOwner": "HOST",
                "activationDisposition": "REBOOT_REQUIRED",
                "driverOrNull": "host-driver",
            }
        )
        fixture.reseal()
        _, inventory, admission = _typed_inputs(
            fixture=fixture,
            profile=STATIC_QUALIFICATION_PROFILE_CONTEXT,
        )
        inventory_closure = resolve_static_inventory_closure(
            inventory,
            admission,
        )
        qualification_binding = bind_static_qualification_profile(
            admission,
            STATIC_QUALIFICATION_PROFILE_CONTEXT,
        )
        static_context = bind_static_capability_context(
            inventory_closure,
            qualification_binding,
            resource_plan_context_for(
                inventory_closure,
                qualification_binding,
            ),
        )
        self.assertEqual("NO", static_context.admin_gate.state.value)
        caller_claim = replace(
            capability_input(),
            admin_gate=GateAssessment.yes(),
        )
        with self.assertRaises(DirectPathVerificationError) as raised:
            _validate_factory_capability_gates(
                caller_claim,
                static_context,
            )
        self.assertEqual("EVIDENCE_INCOMPLETE", raised.exception.code)
        self.assertEqual(
            "capability_input.admin_gate",
            raised.exception.path,
        )

    def test_caller_cannot_self_report_owner_active_over_factory_no(
        self,
    ) -> None:
        fixture = InventoryFixture(
            private=_TRUST_FIXTURE.inventory_private,
            trust=_STATIC_TRUST_CONTEXT,
        )
        fixture.records[0]["owner"].update(
            {
                "hostActive": False,
                "effectiveOwner": "HOST",
                "activationDisposition": "REBOOT_REQUIRED",
                "driverOrNull": "host-driver",
            }
        )
        fixture.reseal()
        _, inventory, admission = _typed_inputs(
            fixture=fixture,
            profile=STATIC_QUALIFICATION_PROFILE_CONTEXT,
        )
        inventory_closure = resolve_static_inventory_closure(
            inventory,
            admission,
        )
        qualification_binding = bind_static_qualification_profile(
            admission,
            STATIC_QUALIFICATION_PROFILE_CONTEXT,
        )
        static_context = bind_static_capability_context(
            inventory_closure,
            qualification_binding,
            resource_plan_context_for(
                inventory_closure,
                qualification_binding,
            ),
        )
        self.assertEqual(
            "NO",
            static_context.owner_active_gate.state.value,
        )
        caller_claim = replace(
            capability_input(),
            owner_active_gate=GateAssessment.yes(),
        )
        with self.assertRaises(DirectPathVerificationError) as raised:
            _validate_factory_capability_gates(
                caller_claim,
                static_context,
            )
        self.assertEqual("EVIDENCE_INCOMPLETE", raised.exception.code)
        self.assertEqual(
            "capability_input.owner_active_gate",
            raised.exception.path,
        )

    def test_arbitrary_resource_plan_hash_is_rejected(self) -> None:
        caller_claim = replace(
            capability_input(),
            resource_plan_hash=digest("0"),
        )
        with self.assertRaises(DirectPathVerificationError) as raised:
            _validate_factory_capability_gates(
                caller_claim,
                STATIC_CAPABILITY_CONTEXT,
            )
        self.assertEqual("EVIDENCE_INCOMPLETE", raised.exception.code)
        self.assertEqual(
            "capability_input.resource_plan_hash",
            raised.exception.path,
        )

    def test_retained_hardware_premise_is_fully_replayed(self) -> None:
        fixture = InventoryFixture(
            private=_TRUST_FIXTURE.inventory_private,
            trust=_STATIC_TRUST_CONTEXT,
        )
        fixture.records[0]["owner"].update(
            {
                "adminEnabled": False,
                "hostActive": False,
                "effectiveOwner": "HOST",
                "activationDisposition": "REBOOT_REQUIRED",
                "driverOrNull": "host-driver",
            }
        )
        fixture.reseal()
        _, inventory, admission = _typed_inputs(
            fixture=fixture,
            profile=STATIC_QUALIFICATION_PROFILE_CONTEXT,
        )
        altered = resolve_static_inventory_closure(inventory, admission)
        forged_closure = forged_inventory_closure_context(
            hardware_premise=altered.hardware_premise,
        )
        forged_context = capability_context_for_inventory_closure(
            forged_closure,
        )
        with self.assertRaises(DirectPathVerificationError) as raised:
            evaluate_guarded_read(
                before_current_vector=authority(),
                capability_input=capability_input(),
                dependencies=dependencies(),
                after_current_vector=authority(),
                availability_read_set=availability_read_set(),
                request_read_set=request_read_set(),
                static_capability_context=forged_context,
                host_snapshot_anchor_binding=(
                    HOST_SNAPSHOT_ANCHOR_BINDING
                ),
                checked_at=CHECKED_AT,
                valid_until=VALID_UNTIL,
            )
        self.assertEqual("EVIDENCE_INCOMPLETE", raised.exception.code)
        self.assertEqual(
            "static_capability_context.inventory_closure",
            raised.exception.path,
        )

    def test_policy_expiry_bounds_authorization_before_evaluation(self) -> None:
        with (
            patch(
                "qman_directpath_core.read_guard.evaluate_capability",
                side_effect=AssertionError(
                    "capability evaluated before policy horizon check"
                ),
            ),
            self.assertRaises(DirectPathVerificationError) as raised,
        ):
            evaluate_guarded_read(
                before_current_vector=authority(),
                capability_input=capability_input(),
                dependencies=dependencies(),
                after_current_vector=authority(),
                availability_read_set=availability_read_set(),
                **closure_arguments(),
                checked_at=CHECKED_AT,
                valid_until=(
                    STATIC_ADMISSION_CONTEXT.policy.expires_at
                    + timedelta(microseconds=1)
                ),
            )
        self.assertEqual("STALE_AUTHORITY", raised.exception.code)
        self.assertEqual("valid_until", raised.exception.path)

    def test_profile_expiry_bounds_authorization_before_evaluation(
        self,
    ) -> None:
        with (
            patch(
                "qman_directpath_core.read_guard.evaluate_capability",
                side_effect=AssertionError(
                    "capability evaluated before profile horizon check"
                ),
            ),
            self.assertRaises(DirectPathVerificationError) as raised,
        ):
            evaluate_guarded_read(
                before_current_vector=authority(),
                capability_input=capability_input(),
                dependencies=dependencies(),
                after_current_vector=authority(),
                availability_read_set=availability_read_set(),
                **closure_arguments(),
                checked_at=CHECKED_AT,
                valid_until=(
                    STATIC_QUALIFICATION_PROFILE_CONTEXT.expires_at
                    + timedelta(microseconds=1)
                ),
            )
        self.assertEqual("STALE_AUTHORITY", raised.exception.code)
        self.assertEqual("valid_until", raised.exception.path)

    def test_availability_change_recomputes_but_old_token_cannot_authorize(
        self,
    ) -> None:
        initial = evaluate_guarded_read(
            before_current_vector=authority(),
            capability_input=capability_input(),
            dependencies=dependencies(),
            after_current_vector=authority(),
            availability_read_set=availability_read_set(),
            **closure_arguments(),
            checked_at=CHECKED_AT,
            valid_until=VALID_UNTIL,
        )
        advanced = replace(
            authority(),
            availability_authority_resource_version=20,
        )
        busy_read_set = availability_read_set(
            authority_resource_version=20,
            blocking_claim_digests=(digest("f"),),
        )
        advanced = replace(
            advanced,
            availability_read_set_digest=busy_read_set.read_set_digest,
        )
        changed_dependencies = replace(
            dependencies(),
            availability_read_set_digest=busy_read_set.read_set_digest,
        )
        busy = Reason(
            code="DEPENDENCY_BUSY",
            stage="reservation",
            devices=("device-0000:65:00.0",),
            details=(
                ReasonDetail(
                    key="leaseState",
                    value_type="TEXT",
                    value="BUSY",
                ),
            ),
        )
        changed_input = replace(
            capability_input(),
            availability_gate=GateAssessment.no(busy),
        )
        recomputed = evaluate_guarded_read(
            before_current_vector=advanced,
            capability_input=changed_input,
            dependencies=changed_dependencies,
            after_current_vector=advanced,
            availability_read_set=busy_read_set,
            **closure_arguments(),
            checked_at=CHECKED_AT,
            valid_until=VALID_UNTIL,
        )

        self.assertEqual(
            initial.evaluation.semantic_hash,
            recomputed.evaluation.semantic_hash,
        )
        self.assertTrue(initial.evaluation.decision.available)
        self.assertFalse(recomputed.evaluation.decision.available)
        self.assertNotEqual(
            initial.evaluation.decision.decision_hash,
            recomputed.evaluation.decision.decision_hash,
        )
        self.assertNotEqual(
            initial.authorization.authority_vector_digest,
            recomputed.authorization.authority_vector_digest,
        )
        self.assertTrue(
            semantic_cache_reusable(
                initial.authorization,
                changed_dependencies,
            )
        )
        with self.assertRaises(DirectPathVerificationError) as raised:
            GuardedCapabilityRead(
                evaluation=initial.evaluation,
                authorization=recomputed.authorization,
            )
        self.assertEqual(raised.exception.code, "STALE_AUTHORITY")
        with self.assertRaises(DirectPathVerificationError) as raised:
            assert_current(
                initial.authorization,
                advanced,
                at=CHECKED_AT,
                expected_decision_digest=(initial.evaluation.decision.decision_hash),
                dependencies=dependencies(),
            )
        self.assertEqual(raised.exception.code, "STALE_AUTHORITY")
        assert_current(
            recomputed.authorization,
            advanced,
            at=CHECKED_AT,
            expected_decision_digest=(recomputed.evaluation.decision.decision_hash),
            dependencies=changed_dependencies,
        )

    def test_blocking_read_set_cannot_be_paired_with_a_yes_gate(self) -> None:
        busy_read_set = availability_read_set(
            authority_resource_version=20,
            blocking_claim_digests=(digest("f"),),
        )
        busy_dependencies = replace(
            dependencies(),
            availability_read_set_digest=busy_read_set.read_set_digest,
        )
        busy_authority = replace(
            authority(),
            availability_authority_resource_version=20,
            availability_read_set_digest=busy_read_set.read_set_digest,
        )

        with self.assertRaises(DirectPathVerificationError) as raised:
            evaluate_guarded_read(
                before_current_vector=busy_authority,
                capability_input=capability_input(),
                dependencies=busy_dependencies,
                after_current_vector=busy_authority,
                availability_read_set=busy_read_set,
                **closure_arguments(),
                checked_at=CHECKED_AT,
                valid_until=VALID_UNTIL,
            )
        self.assertEqual(raised.exception.code, "STALE_AUTHORITY")

        quarantine_read_set = availability_read_set(
            authority_resource_version=21,
            blocking_quarantine_record_digests=(digest("e"),),
        )
        wrong_reason = replace(
            capability_input(),
            availability_gate=GateAssessment.no(
                Reason(
                    code="DEPENDENCY_BUSY",
                    stage="reservation",
                    devices=("device-0000:65:00.0",),
                )
            ),
        )
        with self.assertRaises(DirectPathVerificationError) as raised:
            evaluate_guarded_read(
                before_current_vector=replace(
                    authority(),
                    availability_authority_resource_version=21,
                    availability_read_set_digest=(quarantine_read_set.read_set_digest),
                ),
                capability_input=wrong_reason,
                dependencies=replace(
                    dependencies(),
                    availability_read_set_digest=(quarantine_read_set.read_set_digest),
                ),
                after_current_vector=replace(
                    authority(),
                    availability_authority_resource_version=21,
                    availability_read_set_digest=(quarantine_read_set.read_set_digest),
                ),
                availability_read_set=quarantine_read_set,
                **closure_arguments(),
                checked_at=CHECKED_AT,
                valid_until=VALID_UNTIL,
            )
        self.assertEqual(raised.exception.code, "STALE_AUTHORITY")

    def test_closure_receipt_must_match_current_authority(self) -> None:
        facts, closure = closure_context()
        stale_facts = replace(
            facts,
            inventory_verification_receipt_digest=digest("0"),
        )
        stale_closure = resolve_dependency_closure(
            facts=stale_facts,
            payload_device_uids=(STATIC_ADMISSION_CONTEXT.request.payload_device_uids),
            limits=STATIC_ADMISSION_CONTEXT.policy.closure_limits,
        )

        with self.assertRaises(DirectPathVerificationError) as raised:
            evaluate_guarded_read(
                before_current_vector=authority(),
                capability_input=capability_input(),
                dependencies=dependencies(),
                after_current_vector=authority(),
                availability_read_set=availability_read_set(),
                request_read_set=request_read_set(),
                host_snapshot_anchor_binding=(
                    HOST_SNAPSHOT_ANCHOR_BINDING
                ),
                static_capability_context=(
                    capability_context_for_inventory_closure(
                        forged_inventory_closure_context(
                            facts=stale_facts,
                            result=stale_closure,
                        )
                    )
                ),
                checked_at=CHECKED_AT,
                valid_until=VALID_UNTIL,
            )
        self.assertEqual(raised.exception.code, "EVIDENCE_INCOMPLETE")
        self.assertEqual(
            raised.exception.path,
            "static_capability_context.inventory_closure",
        )

    def test_availability_members_must_equal_closure_members(self) -> None:
        wrong_read_set = availability_read_set(
            member_device_uids=("device-b",),
        )
        wrong_dependencies = replace(
            dependencies(),
            availability_read_set_digest=wrong_read_set.read_set_digest,
        )
        wrong_authority = replace(
            authority(),
            availability_read_set_digest=wrong_read_set.read_set_digest,
        )

        with self.assertRaises(DirectPathVerificationError) as raised:
            evaluate_guarded_read(
                before_current_vector=wrong_authority,
                capability_input=capability_input(),
                dependencies=wrong_dependencies,
                after_current_vector=wrong_authority,
                availability_read_set=wrong_read_set,
                **closure_arguments(),
                checked_at=CHECKED_AT,
                valid_until=VALID_UNTIL,
            )
        self.assertEqual(raised.exception.code, "STALE_AUTHORITY")
        self.assertEqual(
            raised.exception.path,
            "availability_read_set.member_versions",
        )

    def test_availability_member_versions_must_match_inventory(self) -> None:
        stale_read_set = availability_read_set(
            device_generation=4,
            resource_version=12,
        )
        stale_dependencies = replace(
            dependencies(),
            availability_read_set_digest=stale_read_set.read_set_digest,
        )
        stale_authority = replace(
            authority(),
            availability_read_set_digest=stale_read_set.read_set_digest,
        )

        with self.assertRaises(DirectPathVerificationError) as raised:
            evaluate_guarded_read(
                before_current_vector=stale_authority,
                capability_input=capability_input(),
                dependencies=stale_dependencies,
                after_current_vector=stale_authority,
                availability_read_set=stale_read_set,
                **closure_arguments(),
                checked_at=CHECKED_AT,
                valid_until=VALID_UNTIL,
            )
        self.assertEqual(raised.exception.code, "STALE_AUTHORITY")
        self.assertEqual(
            raised.exception.path,
            "availability_read_set.member_versions[0]",
        )

    def test_closure_artifacts_cannot_be_mixed_or_partial(self) -> None:
        facts, closure = closure_context()
        assert closure.bundle is not None
        mismatched_reference = replace(
            capability_input(),
            bundle=replace(
                capability_input().bundle,
                document_id="bundle:stale",
            ),
        )
        with self.assertRaises(DirectPathVerificationError) as raised:
            evaluate_guarded_read(
                before_current_vector=authority(),
                capability_input=mismatched_reference,
                dependencies=dependencies(),
                after_current_vector=authority(),
                availability_read_set=availability_read_set(),
                request_read_set=request_read_set(),
                host_snapshot_anchor_binding=(
                    HOST_SNAPSHOT_ANCHOR_BINDING
                ),
                static_capability_context=STATIC_CAPABILITY_CONTEXT,
                checked_at=CHECKED_AT,
                valid_until=VALID_UNTIL,
            )
        self.assertEqual(raised.exception.code, "STALE_AUTHORITY")
        self.assertEqual(raised.exception.path, "capability_input.bundle")

        forged_result = replace(closure, edges=())
        with self.assertRaises(DirectPathVerificationError) as raised:
            evaluate_guarded_read(
                before_current_vector=authority(),
                capability_input=capability_input(),
                dependencies=dependencies(),
                after_current_vector=authority(),
                availability_read_set=availability_read_set(),
                request_read_set=request_read_set(),
                host_snapshot_anchor_binding=(
                    HOST_SNAPSHOT_ANCHOR_BINDING
                ),
                static_capability_context=(
                    capability_context_for_inventory_closure(
                        forged_inventory_closure_context(
                            result=forged_result,
                        )
                    )
                ),
                checked_at=CHECKED_AT,
                valid_until=VALID_UNTIL,
            )
        self.assertEqual(raised.exception.code, "EVIDENCE_INCOMPLETE")
        self.assertEqual(
            raised.exception.path,
            "static_capability_context.inventory_closure",
        )

        failed_facts = replace(
            facts,
            devices=(),
        )
        failed_closure = resolve_dependency_closure(
            facts=failed_facts,
            payload_device_uids=(STATIC_ADMISSION_CONTEXT.request.payload_device_uids),
            limits=STATIC_ADMISSION_CONTEXT.policy.closure_limits,
        )
        self.assertFalse(failed_closure.success)
        with self.assertRaises(DirectPathVerificationError) as raised:
            evaluate_guarded_read(
                before_current_vector=authority(),
                capability_input=capability_input(),
                dependencies=dependencies(),
                after_current_vector=authority(),
                availability_read_set=availability_read_set(),
                request_read_set=request_read_set(),
                host_snapshot_anchor_binding=(
                    HOST_SNAPSHOT_ANCHOR_BINDING
                ),
                static_capability_context=(
                    capability_context_for_inventory_closure(
                        forged_inventory_closure_context(
                            facts=failed_facts,
                            result=failed_closure,
                        )
                    )
                ),
                checked_at=CHECKED_AT,
                valid_until=VALID_UNTIL,
            )
        self.assertEqual(raised.exception.code, "EVIDENCE_INCOMPLETE")
        self.assertEqual(
            raised.exception.path,
            "static_capability_context.inventory_closure",
        )

    def test_closure_roots_and_approved_limits_cannot_be_replayed(self) -> None:
        facts, baseline = closure_context()
        payload_device_uids = STATIC_ADMISSION_CONTEXT.request.payload_device_uids
        wrong_root = resolve_dependency_closure(
            facts=facts,
            payload_device_uids=("urn:qman:directpath:device:v1:forged-root",),
            limits=STATIC_ADMISSION_CONTEXT.policy.closure_limits,
        )
        relaxed_limits = resolve_dependency_closure(
            facts=facts,
            payload_device_uids=payload_device_uids,
            limits=ClosureLimits(max_devices=512, max_edges=8192),
        )
        self.assertFalse(wrong_root.success)
        self.assertTrue(relaxed_limits.success)
        self.assertNotEqual(
            baseline.closure_request.request_digest,
            wrong_root.closure_request.request_digest,
        )
        self.assertNotEqual(
            baseline.closure_request.request_digest,
            relaxed_limits.closure_request.request_digest,
        )

        for replayed in (wrong_root, relaxed_limits):
            with self.subTest(request=replayed.closure_request):
                with self.assertRaises(DirectPathVerificationError) as raised:
                    evaluate_guarded_read(
                        before_current_vector=authority(),
                        capability_input=capability_input(),
                        dependencies=dependencies(),
                        after_current_vector=authority(),
                        availability_read_set=availability_read_set(),
                        request_read_set=request_read_set(),
                        host_snapshot_anchor_binding=(
                            HOST_SNAPSHOT_ANCHOR_BINDING
                        ),
                        static_capability_context=(
                            capability_context_for_inventory_closure(
                                forged_inventory_closure_context(
                                    result=replayed,
                                )
                            )
                        ),
                        checked_at=CHECKED_AT,
                        valid_until=VALID_UNTIL,
                    )
                self.assertEqual(
                    raised.exception.code,
                    "EVIDENCE_INCOMPLETE",
                )
                self.assertEqual(
                    raised.exception.path,
                    "static_capability_context.inventory_closure",
                )

    def test_api_has_no_io_callback_and_result_is_frozen(self) -> None:
        parameters = inspect.signature(evaluate_guarded_read).parameters
        self.assertEqual(
            tuple(parameters),
            (
                "before_current_vector",
                "capability_input",
                "dependencies",
                "after_current_vector",
                "availability_read_set",
                "request_read_set",
                "static_capability_context",
                "host_snapshot_anchor_binding",
                "checked_at",
                "valid_until",
            ),
        )
        self.assertTrue(
            all(
                parameter.kind is inspect.Parameter.KEYWORD_ONLY
                for parameter in parameters.values()
            )
        )
        with (
            patch("builtins.open", side_effect=AssertionError("unexpected I/O")),
            patch(
                "pathlib.Path.open",
                side_effect=AssertionError("unexpected I/O"),
            ),
        ):
            result = evaluate_guarded_read(
                before_current_vector=authority(),
                capability_input=capability_input(),
                dependencies=dependencies(),
                after_current_vector=authority(),
                availability_read_set=availability_read_set(),
                **closure_arguments(),
                checked_at=CHECKED_AT,
                valid_until=VALID_UNTIL,
            )
        with self.assertRaises(FrozenInstanceError):
            result.authorization = result.authorization  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
