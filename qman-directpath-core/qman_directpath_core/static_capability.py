"""Factory-only binding of static inventory and qualification verification.

This component proves only that three verifier-produced contexts retain the
same exact static admission, inventory closure, qualification profile, and
structurally verified guest resource plan.  It is not E4 evidence, a
repository read, product integration, solver proof, or authority for a side
effect.
"""

from __future__ import annotations

from dataclasses import dataclass

from ._verified import FactoryVerified, require_factory_verified
from .canonical import canonical_json_bytes, sha256_digest
from .capability import GateAssessment
from .errors import require
from .inventory_closure_factory import (
    VerifiedStaticInventoryClosureContext,
)
from .qualification_profile import (
    StructuralStaticQualificationBindingContext,
)
from .resource_plan import (
    VerifiedGuestResourcePlanContext,
    replay_guest_resource_plan_context,
)


def _subject(
    inventory_closure: VerifiedStaticInventoryClosureContext,
    qualification_binding: StructuralStaticQualificationBindingContext,
    resource_plan: VerifiedGuestResourcePlanContext,
    *,
    context_digest: str | None,
) -> dict[str, object]:
    result = inventory_closure.result
    bundle_digest = None if result.bundle is None else result.bundle.bundle_hash
    hardware_premise = inventory_closure.hardware_premise
    return {
        "subjectType": "VERIFIED_STATIC_CAPABILITY_CONTEXT",
        "schemaVersion": 1,
        "staticAdmissionContextDigest": (inventory_closure.admission.context_digest),
        "inventorySnapshotDigest": (inventory_closure.inventory.snapshot_content_hash),
        "inventoryTrustContextDigest": (
            inventory_closure.inventory.trust.context_digest
        ),
        "inventoryVerificationReceiptDigest": (
            inventory_closure.inventory.inventory_verification_receipt_digest
        ),
        "inventoryVerifierIdentityDigest": (
            inventory_closure.inventory.inventory_verifier_identity_digest
        ),
        "closureFactsDigest": inventory_closure.facts.facts_digest,
        "closureRequestDigest": result.closure_request.request_digest,
        "closureSuccess": result.success,
        "dependencyBundleDigestOrNull": bundle_digest,
        "resetContractSetDigestOrNull": (result.reset_contract_set_digest),
        "hardwarePremiseDigest": hardware_premise.premise_digest,
        "factoryHardwareGate": {
            "state": hardware_premise.hardware_gate.state.value,
            "reasons": [
                reason.to_wire()
                for reason in hardware_premise.hardware_gate.reasons
            ],
        },
        "factoryTechnicalGate": {
            "state": hardware_premise.technical_gate.state.value,
            "reasons": [
                reason.to_wire()
                for reason in hardware_premise.technical_gate.reasons
            ],
        },
        "factoryAdminGate": {
            "state": hardware_premise.admin_gate.state.value,
            "reasons": [
                reason.to_wire()
                for reason in hardware_premise.admin_gate.reasons
            ],
        },
        "factoryOwnerActiveGate": {
            "state": hardware_premise.owner_active_gate.state.value,
            "reasons": [
                reason.to_wire()
                for reason in hardware_premise.owner_active_gate.reasons
            ],
        },
        "hardwarePremiseAuthorityBoundary": (
            hardware_premise.authority_boundary
        ),
        "hardwarePremiseProductAuthorized": (
            hardware_premise.product_authorized
        ),
        "resourcePlanContextDigest": resource_plan.context_digest,
        "resourcePlanHash": resource_plan.plan_hash,
        "resourcePlanAuthorityBoundary": resource_plan.authority_boundary,
        "resourcePlanProductAuthorized": resource_plan.product_authorized,
        "qualificationBindingContextDigest": (qualification_binding.context_digest),
        "qualificationProfileContextDigest": (
            qualification_binding.profile.context_digest
        ),
        "profileHash": qualification_binding.profile.profile_hash,
        "profileSemanticDigest": (
            qualification_binding.profile.profile_semantic_digest
        ),
        "qualificationVerificationDisposition": (
            qualification_binding.verification_disposition
        ),
        "qualificationAuthorityBoundary": (
            qualification_binding.authority_boundary
        ),
        "qualificationComponentAuthority": (
            qualification_binding.component_authority
        ),
        "qualificationProductAuthorized": (
            qualification_binding.product_authorized
        ),
        "qualificationAuthorizationBlockers": list(
            qualification_binding.authorization_blockers
        ),
        "contextDigest": context_digest,
    }


@dataclass(frozen=True, slots=True, init=False)
class VerifiedStaticCapabilityContext(FactoryVerified):
    """Exact inventory-closure/profile binding for one static admission."""

    inventory_closure: VerifiedStaticInventoryClosureContext
    qualification_binding: StructuralStaticQualificationBindingContext
    resource_plan: VerifiedGuestResourcePlanContext
    hardware_gate: GateAssessment
    technical_gate: GateAssessment
    admin_gate: GateAssessment
    owner_active_gate: GateAssessment
    resource_plan_hash: str
    hardware_premise_digest: str
    hardware_premise_authority_boundary: str
    hardware_premise_product_authorized: bool
    context_digest: str

    def to_subject(self) -> dict[str, object]:
        return _subject(
            self.inventory_closure,
            self.qualification_binding,
            self.resource_plan,
            context_digest=self.context_digest,
        )


def bind_static_capability_context(
    inventory_closure: VerifiedStaticInventoryClosureContext,
    qualification_binding: StructuralStaticQualificationBindingContext,
    resource_plan: VerifiedGuestResourcePlanContext,
) -> VerifiedStaticCapabilityContext:
    """Bind all verified branches to one exact static admission.

    The result remains a side-effect-free component value.  It makes no claim
    about E4 repository proof, linearizable currentness, leases, or CAS.
    """

    require_factory_verified(
        inventory_closure,
        VerifiedStaticInventoryClosureContext,
        code="STATIC_CAPABILITY_INPUT_INVALID",
        path="inventory_closure",
        message=("inventory closure must come from resolve_static_inventory_closure"),
    )
    require_factory_verified(
        qualification_binding,
        StructuralStaticQualificationBindingContext,
        code="STATIC_CAPABILITY_INPUT_INVALID",
        path="qualification_binding",
        message=(
            "qualification binding must come from bind_static_qualification_profile"
        ),
    )
    require(
        type(qualification_binding)
        is StructuralStaticQualificationBindingContext,
        "STATIC_CAPABILITY_INPUT_INVALID",
        "qualification_binding",
        "subclassed qualification bindings are not accepted",
    )
    qualification_binding.__post_init__()
    replay_guest_resource_plan_context(resource_plan)
    require(
        inventory_closure.admission == qualification_binding.admission
        and inventory_closure.admission.context_digest
        == qualification_binding.admission.context_digest,
        "STATIC_CAPABILITY_ADMISSION_MISMATCH",
        "staticCapability.admission",
        (
            "inventory closure and qualification profile must bind the "
            "same exact static admission"
        ),
    )
    require(
        resource_plan.inventory_closure == inventory_closure
        and resource_plan.qualification_binding == qualification_binding,
        "STATIC_CAPABILITY_RESOURCE_PLAN_MISMATCH",
        "staticCapability.resourcePlan",
        (
            "resource plan must bind the same exact inventory closure and "
            "qualification profile"
        ),
    )
    subject = _subject(
        inventory_closure,
        qualification_binding,
        resource_plan,
        context_digest=None,
    )
    context_digest = sha256_digest(canonical_json_bytes(subject))
    return VerifiedStaticCapabilityContext._construct(
        inventory_closure=inventory_closure,
        qualification_binding=qualification_binding,
        resource_plan=resource_plan,
        hardware_gate=inventory_closure.hardware_premise.hardware_gate,
        technical_gate=inventory_closure.hardware_premise.technical_gate,
        admin_gate=inventory_closure.hardware_premise.admin_gate,
        owner_active_gate=(
            inventory_closure.hardware_premise.owner_active_gate
        ),
        resource_plan_hash=resource_plan.plan_hash,
        hardware_premise_digest=(
            inventory_closure.hardware_premise.premise_digest
        ),
        hardware_premise_authority_boundary=(
            inventory_closure.hardware_premise.authority_boundary
        ),
        hardware_premise_product_authorized=(
            inventory_closure.hardware_premise.product_authorized
        ),
        context_digest=context_digest,
    )


__all__ = [
    "VerifiedStaticCapabilityContext",
    "bind_static_capability_context",
]
