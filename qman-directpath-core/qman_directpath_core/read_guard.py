"""Pure read-side coordination for capability evaluation.

The caller is responsible for fetching ``before_current_vector`` and
``after_current_vector`` from independent authorities.  This module accepts no
I/O callback and performs no reads itself.  It binds the selected immutable
inventory, live HostSnapshot rollback-anchor evidence, and qualification
inputs to the before vector, evaluates capability, creates an authorization,
and verifies the after vector immediately before returning the response.
Supplying vectors or retained anchor bytes is not repository/external-authority
read proof.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from .admission import VerifiedStaticAdmissionContext
from .authority import (
    AvailabilityReadSet,
    BoundCapabilityAuthorization,
    CapabilityAuthorityDisposition,
    CurrentAuthorityVector,
    RequestReadSet,
    ScopedCapabilityDependencies,
    _bind_authorization,
    assert_current,
)
from .capability import (
    CapabilityEvaluation,
    CapabilityInput,
    EvaluationContext,
    OperationContext,
    evaluate_capability,
)
from .canonical import canonical_json_bytes
from .closure import (
    DependencyClosureResult,
    VerifiedClosureFacts,
    resolve_dependency_closure,
)
from .errors import DirectPathVerificationError, fail
from .host_snapshot_anchor import (
    VerifiedHostSnapshotAnchorBinding,
    replay_host_snapshot_anchor_binding,
)
from .inventory_closure_factory import (
    VerifiedStaticInventoryClosureContext,
    resolve_static_inventory_closure,
)
from .qualification_profile import bind_static_qualification_profile
from .static_capability import (
    VerifiedStaticCapabilityContext,
    bind_static_capability_context,
)
from ._verified import require_factory_verified


_COMPONENT_AUTHORIZATION_BLOCKERS = frozenset(
    {
        "PRODUCT_HOST_SNAPSHOT_AUTHORITY_ADAPTER_REQUIRED",
        "PRODUCT_INVENTORY_COLLECTOR_PUBLISHER_REQUIRED",
        "PRODUCT_REPOSITORY_LEASE_CAS_REQUIRED",
        "PRODUCT_RESOURCE_PLANNER_REQUIRED",
    }
)


@dataclass(frozen=True, slots=True)
class GuardedCapabilityRead:
    """Immutable evaluation and the exact authority token that guards it."""

    evaluation: CapabilityEvaluation
    authorization: BoundCapabilityAuthorization

    def __post_init__(self) -> None:
        if not isinstance(self.evaluation, CapabilityEvaluation):
            fail(
                "CAPABILITY_INPUT_INVALID",
                "guarded_read.evaluation",
                "expected CapabilityEvaluation",
            )
        if not isinstance(
            self.authorization,
            BoundCapabilityAuthorization,
        ):
            fail(
                "CAPABILITY_INPUT_INVALID",
                "guarded_read.authorization",
                "expected BoundCapabilityAuthorization",
            )
        if self.evaluation.decision.decision_hash != self.authorization.decision_digest:
            fail(
                "STALE_AUTHORITY",
                "guarded_read.authorization.decision_digest",
                "authorization does not bind this capability evaluation",
            )
        if self.authorization.authority_disposition.product_authorized:
            fail(
                "AUTHORITY_DISPOSITION_INVALID",
                "guarded_read.authorization.authority_disposition",
                "portable guarded reads cannot claim product authority",
            )


def _binding(actual: str, expected: str, path: str, description: str) -> None:
    if actual != expected:
        fail(
            "STALE_AUTHORITY",
            path,
            f"{description} is not bound to the selected dependency set",
        )


def _validate_selected_bindings(
    capability_input: CapabilityInput,
    dependencies: ScopedCapabilityDependencies,
) -> None:
    _binding(
        capability_input.request_hash,
        dependencies.request_digest,
        "capability_input.request_hash",
        "request",
    )
    _binding(
        capability_input.closure_request_hash,
        dependencies.closure_request_digest,
        "capability_input.closure_request_hash",
        "dependency closure request",
    )
    _binding(
        capability_input.policy_hash,
        dependencies.policy_digest,
        "capability_input.policy_hash",
        "policy",
    )
    _binding(
        capability_input.profile_hash,
        dependencies.qualification_profile_digest,
        "capability_input.profile_hash",
        "qualification profile",
    )
    _binding(
        capability_input.profile_semantic_hash,
        dependencies.qualification_profile_semantic_digest,
        "capability_input.profile_semantic_hash",
        "selected qualification semantics",
    )
    _binding(
        capability_input.bundle.content_hash,
        dependencies.dependency_bundle_digest,
        "capability_input.bundle.content_hash",
        "dependency bundle",
    )
    _binding(
        capability_input.reset_contract.content_hash,
        dependencies.reset_contract_digest,
        "capability_input.reset_contract.content_hash",
        "reset contract",
    )
    _binding(
        capability_input.snapshot_semantic_hash,
        dependencies.hardware_snapshot_semantic_digest,
        "capability_input.snapshot_semantic_hash",
        "owner-independent snapshot semantics",
    )


def _validate_factory_capability_gates(
    capability_input: CapabilityInput,
    context: VerifiedStaticCapabilityContext,
) -> None:
    if capability_input.hardware != context.hardware_gate:
        fail(
            "EVIDENCE_INCOMPLETE",
            "capability_input.hardware",
            (
                "hardware gate must exactly equal the factory projection from "
                "the verified V3 inventory and payload roots"
            ),
        )
    if capability_input.technical != context.technical_gate:
        fail(
            "EVIDENCE_INCOMPLETE",
            "capability_input.technical",
            (
                "technical gate must exactly equal the factory closure "
                "premise; caller self-assessment is not accepted"
            ),
        )
    if capability_input.admin_gate != context.admin_gate:
        fail(
            "EVIDENCE_INCOMPLETE",
            "capability_input.admin_gate",
            (
                "administrator gate must exactly equal the factory "
                "projection from the selected payload owner facts"
            ),
        )
    if capability_input.owner_active_gate != context.owner_active_gate:
        fail(
            "EVIDENCE_INCOMPLETE",
            "capability_input.owner_active_gate",
            (
                "owner-active gate must exactly equal the factory "
                "projection from the selected payload owner facts"
            ),
        )
    if capability_input.resource_plan_hash != context.resource_plan_hash:
        fail(
            "EVIDENCE_INCOMPLETE",
            "capability_input.resource_plan_hash",
            (
                "resource-plan hash must exactly equal the structurally "
                "verified plan bound to this static capability context"
            ),
        )


def _validate_before_current(
    dependencies: ScopedCapabilityDependencies,
    before_current_vector: CurrentAuthorityVector,
) -> None:
    _binding(
        dependencies.publisher_snapshot_digest,
        before_current_vector.publisher_snapshot_digest,
        "dependencies.publisher_snapshot_digest",
        "publisher snapshot",
    )
    _binding(
        dependencies.policy_digest,
        before_current_vector.policy_digest,
        "dependencies.policy_digest",
        "policy",
    )
    _binding(
        dependencies.inventory_verifier_identity_digest,
        before_current_vector.inventory_verifier_identity_digest,
        "dependencies.inventory_verifier_identity_digest",
        "verifier identity",
    )
    _binding(
        dependencies.availability_read_set_digest,
        before_current_vector.availability_read_set_digest,
        "dependencies.availability_read_set_digest",
        "selected availability read set",
    )
    _binding(
        dependencies.request_read_set_digest,
        before_current_vector.request_read_set_digest,
        "dependencies.request_read_set_digest",
        "selected request read set",
    )


def _validate_static_request_binding(
    *,
    capability_input: CapabilityInput,
    dependencies: ScopedCapabilityDependencies,
    before_current_vector: CurrentAuthorityVector,
    request_read_set: RequestReadSet,
    static_admission_context: VerifiedStaticAdmissionContext,
    closure_result: DependencyClosureResult,
    valid_until: datetime,
) -> None:
    """Bind one exact current static VM request before any evaluation."""

    if not isinstance(request_read_set, RequestReadSet):
        fail(
            "INVALID_REQUEST_READ_SET",
            "request_read_set",
            "expected a verified RequestReadSet value",
        )
    if not isinstance(
        static_admission_context,
        VerifiedStaticAdmissionContext,
    ):
        fail(
            "EVIDENCE_INCOMPLETE",
            "static_admission_context",
            "expected VerifiedStaticAdmissionContext",
        )
    if (
        capability_input.evaluation_context is not EvaluationContext.VM_REQUEST
        or capability_input.operation_context is not OperationContext.STATIC_ADMISSION
    ):
        fail(
            "CAPABILITY_INPUT_INVALID",
            "capability_input.evaluation_context",
            (
                "guarded request currentness is defined only for "
                "VM_REQUEST/STATIC_ADMISSION"
            ),
        )

    request = static_admission_context.request
    policy = static_admission_context.policy
    if (
        request.document.get("subjectType") != "VM_DIRECTPATH_REQUEST"
        or request.document.get("requestType") != "STATIC"
        or request.canonical_request.get("requestType") != "STATIC"
    ):
        fail(
            "EVIDENCE_INCOMPLETE",
            "static_admission_context.request",
            "context must contain one verified STATIC VM request entity",
        )
    expected_request_values = (
        (
            request_read_set.vm_id,
            request.document["vmId"],
            "request_read_set.vm_id",
        ),
        (
            request_read_set.request_version,
            request.request_version,
            "request_read_set.request_version",
        ),
        (
            request_read_set.request_resource_version,
            request.resource_version,
            "request_read_set.request_resource_version",
        ),
        (
            request_read_set.request_hash,
            request.request_hash,
            "request_read_set.request_hash",
        ),
        (
            request_read_set.request_entity_digest,
            request.entity_digest,
            "request_read_set.request_entity_digest",
        ),
    )
    for actual, expected, path in expected_request_values:
        if actual != expected:
            fail(
                "STALE_AUTHORITY",
                path,
                "current request row does not match the verified request",
            )
    _binding(
        request_read_set.read_set_digest,
        dependencies.request_read_set_digest,
        "request_read_set.read_set_digest",
        "request row observation",
    )
    _binding(
        request_read_set.read_set_digest,
        before_current_vector.request_read_set_digest,
        "request_read_set.read_set_digest",
        "current request authority vector",
    )
    if request_read_set.authority_id != before_current_vector.request_authority_id:
        fail(
            "STALE_AUTHORITY",
            "request_read_set.authority_id",
            "request row observation is not from the current authority",
        )

    policy_hash = policy.policy_hash
    for actual, path, description in (
        (
            request.policy_hash,
            "static_admission_context.request.policy_hash",
            "request policy binding",
        ),
        (
            dependencies.policy_digest,
            "dependencies.policy_digest",
            "selected policy",
        ),
        (
            before_current_vector.policy_digest,
            "before_current_vector.policy_digest",
            "current policy",
        ),
        (
            capability_input.policy_hash,
            "capability_input.policy_hash",
            "capability policy input",
        ),
    ):
        _binding(actual, policy_hash, path, description)

    if not isinstance(closure_result, DependencyClosureResult):
        fail(
            "EVIDENCE_INCOMPLETE",
            "closure_result",
            "expected DependencyClosureResult",
        )
    closure_request = static_admission_context.closure_request
    if closure_result.closure_request != closure_request:
        fail(
            "STALE_AUTHORITY",
            "closure_result.closure_request",
            (
                "closure roots, provenance, or limits do not exactly match "
                "the verified static admission context"
            ),
        )
    if (
        closure_request.payload_device_uids != request.payload_device_uids
        or closure_request.request_provenance_digest != request.request_hash
        or closure_request.policy_provenance_digest != policy_hash
        or closure_request.limits != policy.closure_limits
    ):
        fail(
            "EVIDENCE_INCOMPLETE",
            "static_admission_context.closure_request",
            "closure request was not exactly derived from request and policy",
        )
    _binding(
        dependencies.closure_request_digest,
        closure_request.request_digest,
        "dependencies.closure_request_digest",
        "verified static closure request",
    )
    _binding(
        capability_input.closure_request_hash,
        closure_request.request_digest,
        "capability_input.closure_request_hash",
        "verified static closure request",
    )
    _binding(
        dependencies.request_digest,
        request.request_hash,
        "dependencies.request_digest",
        "verified static request",
    )
    _binding(
        capability_input.request_hash,
        request.request_hash,
        "capability_input.request_hash",
        "verified static request",
    )

    if (
        not isinstance(valid_until, datetime)
        or valid_until.tzinfo is None
        or valid_until.utcoffset() is None
    ):
        fail(
            "TIME_INVALID",
            "valid_until",
            "expected a timezone-aware datetime",
        )
    if valid_until.astimezone(timezone.utc) > policy.expires_at:
        fail(
            "STALE_AUTHORITY",
            "valid_until",
            "authorization window exceeds verified policy expiry",
        )


def _validate_availability_gate(
    capability_input: CapabilityInput,
    availability_read_set: AvailabilityReadSet,
) -> None:
    required_codes: set[str] = set()
    if availability_read_set.blocking_claim_digests:
        required_codes.add("DEPENDENCY_BUSY")
    if availability_read_set.blocking_quarantine_record_digests:
        required_codes.add("DEVICE_QUARANTINED")
    if not required_codes:
        return
    actual_codes = {
        reason.code for reason in capability_input.availability_gate.reasons
    }
    if (
        capability_input.availability_gate.state.value != "NO"
        or not required_codes.issubset(actual_codes)
    ):
        fail(
            "STALE_AUTHORITY",
            "capability_input.availability_gate",
            (
                "blocking availability authority evidence requires a NO gate "
                f"with reasons {sorted(required_codes)!r}"
            ),
        )


def _validate_static_inventory_context(
    context: VerifiedStaticInventoryClosureContext,
    before_current_vector: CurrentAuthorityVector,
) -> None:
    require_factory_verified(
        context,
        VerifiedStaticInventoryClosureContext,
        code="EVIDENCE_INCOMPLETE",
        path="static_capability_context.inventory_closure",
        message=("context must come from resolve_static_inventory_closure"),
    )
    replayed = resolve_static_inventory_closure(
        context.inventory,
        context.admission,
    )
    if replayed != context:
        fail(
            "EVIDENCE_INCOMPLETE",
            "static_capability_context.inventory_closure",
            (
                "retained facts/result do not exactly match the verified "
                "inventory and static admission"
            ),
        )

    inventory = context.inventory
    expected_bindings = (
        (
            before_current_vector.host_authority_id,
            inventory.host_id,
            "before_current_vector.host_authority_id",
            "inventory host authority",
        ),
        (
            before_current_vector.host_authority_resource_version,
            inventory.observed_authority_resource_version,
            "before_current_vector.host_authority_resource_version",
            "inventory current-pointer resource version",
        ),
        (
            inventory.snapshot_authority_resource_version,
            inventory.observed_authority_resource_version,
            "static_capability_context.inventory_closure.inventory."
            "snapshot_authority_resource_version",
            "committed snapshot authority version",
        ),
        (
            before_current_vector.publisher_snapshot_digest,
            inventory.snapshot_content_hash,
            "before_current_vector.publisher_snapshot_digest",
            "verified inventory snapshot",
        ),
        (
            before_current_vector.policy_digest,
            inventory.policy_hash,
            "before_current_vector.policy_digest",
            "inventory policy",
        ),
        (
            before_current_vector.trust_root_digest,
            inventory.trust.root_set_digest,
            "before_current_vector.trust_root_digest",
            "inventory trust root",
        ),
        (
            before_current_vector.key_ring_sequence,
            inventory.trust.key_ring_sequence,
            "before_current_vector.key_ring_sequence",
            "inventory trust ring sequence",
        ),
        (
            before_current_vector.key_ring_digest,
            inventory.trust.key_ring_digest,
            "before_current_vector.key_ring_digest",
            "inventory trust ring",
        ),
        (
            before_current_vector.inventory_verification_receipt_digest,
            inventory.inventory_verification_receipt_digest,
            "before_current_vector.inventory_verification_receipt_digest",
            "inventory verification receipt",
        ),
        (
            before_current_vector.inventory_verifier_identity_digest,
            inventory.inventory_verifier_identity_digest,
            "before_current_vector.inventory_verifier_identity_digest",
            "inventory verifier identity",
        ),
    )
    for actual, expected, path, description in expected_bindings:
        if actual != expected:
            fail(
                "STALE_AUTHORITY",
                path,
                f"{description} does not match the verified inventory",
            )


def _validate_static_capability_context(
    context: VerifiedStaticCapabilityContext,
    before_current_vector: CurrentAuthorityVector,
) -> None:
    require_factory_verified(
        context,
        VerifiedStaticCapabilityContext,
        code="EVIDENCE_INCOMPLETE",
        path="static_capability_context",
        message=("context must come from bind_static_capability_context"),
    )
    _validate_static_inventory_context(
        context.inventory_closure,
        before_current_vector,
    )
    try:
        replayed = bind_static_capability_context(
            context.inventory_closure,
            context.qualification_binding,
            context.resource_plan,
        )
    except DirectPathVerificationError:
        fail(
            "EVIDENCE_INCOMPLETE",
            "static_capability_context",
            "retained composite context does not exactly replay",
        )
    if replayed != context:
        fail(
            "EVIDENCE_INCOMPLETE",
            "static_capability_context",
            "retained composite context does not exactly replay",
        )
    replayed_qualification = bind_static_qualification_profile(
        context.qualification_binding.admission,
        context.qualification_binding.profile,
    )
    if replayed_qualification != context.qualification_binding:
        fail(
            "EVIDENCE_INCOMPLETE",
            "static_capability_context.qualification_binding",
            "retained qualification binding does not exactly replay",
        )


def _validate_host_snapshot_anchor_binding(
    *,
    binding: VerifiedHostSnapshotAnchorBinding,
    inventory_closure: VerifiedStaticInventoryClosureContext,
    before_current_vector: CurrentAuthorityVector,
    checked_at: datetime,
    valid_until: datetime,
) -> None:
    require_factory_verified(
        binding,
        VerifiedHostSnapshotAnchorBinding,
        code="EVIDENCE_INCOMPLETE",
        path="host_snapshot_anchor_binding",
        message=(
            "binding must come from verify_host_snapshot_anchor_binding"
        ),
    )
    replay_host_snapshot_anchor_binding(binding)
    inventory = inventory_closure.inventory
    for actual, expected, path, description in (
        (
            binding.trust.context_digest,
            inventory.trust.context_digest,
            "host_snapshot_anchor_binding.trust",
            "inventory trust context",
        ),
        (
            binding.inventory.inventory_verification_receipt_digest,
            inventory.inventory_verification_receipt_digest,
            "host_snapshot_anchor_binding.inventory",
            "verified inventory receipt",
        ),
        (
            binding.host_id,
            inventory.host_id,
            "host_snapshot_anchor_binding.host_id",
            "inventory host",
        ),
        (
            binding.kernel_boot_id,
            inventory.kernel_boot_id,
            "host_snapshot_anchor_binding.kernel_boot_id",
            "inventory kernel boot",
        ),
        (
            binding.host_epoch,
            inventory.host_epoch,
            "host_snapshot_anchor_binding.host_epoch",
            "inventory host epoch",
        ),
        (
            binding.agent_identity,
            inventory.agent_identity,
            "host_snapshot_anchor_binding.agent_identity",
            "inventory agent identity",
        ),
        (
            binding.agent_generation,
            inventory.agent_generation,
            "host_snapshot_anchor_binding.agent_generation",
            "inventory agent generation",
        ),
        (
            binding.accepted_snapshot_epoch,
            inventory.snapshot_epoch,
            "host_snapshot_anchor_binding.accepted_snapshot_epoch",
            "inventory snapshot epoch",
        ),
        (
            binding.accepted_snapshot_content_hash,
            inventory.snapshot_content_hash,
            "host_snapshot_anchor_binding.accepted_snapshot_content_hash",
            "inventory snapshot content",
        ),
        (
            binding.accepted_host_authority_resource_version,
            inventory.snapshot_authority_resource_version,
            "host_snapshot_anchor_binding."
            "accepted_host_authority_resource_version",
            "inventory HostAuthority version",
        ),
        (
            before_current_vector.host_snapshot_anchor_authority_id,
            binding.anchor_authority_id,
            "before_current_vector.host_snapshot_anchor_authority_id",
            "HostSnapshot rollback-anchor authority",
        ),
        (
            before_current_vector.host_snapshot_anchor_version,
            binding.anchor_version,
            "before_current_vector.host_snapshot_anchor_version",
            "HostSnapshot rollback-anchor version",
        ),
        (
            before_current_vector.host_snapshot_anchor_resource_version,
            binding.anchor_resource_version,
            "before_current_vector.host_snapshot_anchor_resource_version",
            "HostSnapshot rollback-anchor resource version",
        ),
        (
            before_current_vector.host_snapshot_anchor_digest,
            binding.anchor_digest,
            "before_current_vector.host_snapshot_anchor_digest",
            "HostSnapshot rollback anchor",
        ),
        (
            before_current_vector.host_snapshot_anchor_freshness_receipt_digest,
            binding.freshness_receipt_digest,
            "before_current_vector."
            "host_snapshot_anchor_freshness_receipt_digest",
            "HostSnapshot rollback-anchor freshness receipt",
        ),
        (
            before_current_vector.host_snapshot_anchor_binding_digest,
            binding.binding_digest,
            "before_current_vector.host_snapshot_anchor_binding_digest",
            "verified HostSnapshot rollback-anchor binding",
        ),
    ):
        if actual != expected:
            fail(
                "STALE_AUTHORITY",
                path,
                f"{description} does not match the verified binding",
            )

    for value, path in (
        (checked_at, "checked_at"),
        (valid_until, "valid_until"),
    ):
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() is None
        ):
            fail("TIME_INVALID", path, "expected a timezone-aware datetime")
    normalized_checked_at = checked_at.astimezone(timezone.utc)
    normalized_valid_until = valid_until.astimezone(timezone.utc)
    if not (
        binding.verified_at
        <= normalized_checked_at
        < binding.freshness_expires_at
    ):
        fail(
            "STALE_AUTHORITY",
            "checked_at",
            "evaluation time is outside the live HostSnapshot anchor window",
        )
    if normalized_valid_until > binding.freshness_expires_at:
        fail(
            "STALE_AUTHORITY",
            "valid_until",
            "authorization window exceeds HostSnapshot anchor freshness",
        )


def _validate_qualification_binding(
    *,
    capability_input: CapabilityInput,
    dependencies: ScopedCapabilityDependencies,
    before_current_vector: CurrentAuthorityVector,
    static_capability_context: VerifiedStaticCapabilityContext,
    host_snapshot_anchor_binding: VerifiedHostSnapshotAnchorBinding,
    checked_at: datetime,
    valid_until: datetime,
) -> None:
    binding = static_capability_context.qualification_binding
    profile = binding.profile
    qualification = profile.qualification
    trust = qualification.trust

    for actual, expected, path, description in (
        (
            capability_input.profile_hash,
            profile.profile_hash,
            "capability_input.profile_hash",
            "verified qualification profile",
        ),
        (
            dependencies.qualification_profile_digest,
            profile.profile_hash,
            "dependencies.qualification_profile_digest",
            "verified qualification profile",
        ),
        (
            capability_input.profile_semantic_hash,
            profile.profile_semantic_digest,
            "capability_input.profile_semantic_hash",
            "verified qualification profile semantics",
        ),
        (
            dependencies.qualification_profile_semantic_digest,
            profile.profile_semantic_digest,
            "dependencies.qualification_profile_semantic_digest",
            "verified qualification profile semantics",
        ),
    ):
        _binding(actual, expected, path, description)

    if (
        dependencies.qualification_record_digests
        != profile.qualification_record_digests
    ):
        fail(
            "STALE_AUTHORITY",
            "dependencies.qualification_record_digests",
            ("qualification records do not exactly match the verified profile"),
        )
    expected_signers = tuple(
        sorted(
            {
                profile.dependency.qualification_signer_key_id,
                qualification.product_release_signer_key_id,
            },
            key=canonical_json_bytes,
        )
    )
    if dependencies.qualification_signer_key_ids != expected_signers:
        fail(
            "STALE_AUTHORITY",
            "dependencies.qualification_signer_key_ids",
            (
                "qualification signers do not exactly match the verified "
                "record and catalog"
            ),
        )
    if capability_input.admission_requirement is not (binding.admission_requirement):
        fail(
            "STALE_AUTHORITY",
            "capability_input.admission_requirement",
            "capability admission does not match the verified request",
        )
    if capability_input.policy_mode.value != binding.admission.policy.admission_mode:
        fail(
            "STALE_AUTHORITY",
            "capability_input.policy_mode",
            "capability mode does not match the verified policy",
        )

    current_bindings = (
        (
            before_current_vector.policy_id,
            binding.admission.policy.policy_id,
            "before_current_vector.policy_id",
            "capability policy identity",
        ),
        (
            before_current_vector.policy_version,
            binding.admission.policy.policy_version,
            "before_current_vector.policy_version",
            "capability policy version",
        ),
        (
            before_current_vector.policy_digest,
            binding.admission.policy.policy_hash,
            "before_current_vector.policy_digest",
            "capability policy",
        ),
        (
            before_current_vector.catalog_id,
            qualification.catalog_id,
            "before_current_vector.catalog_id",
            "supported catalog identity",
        ),
        (
            before_current_vector.catalog_sequence,
            qualification.catalog_sequence,
            "before_current_vector.catalog_sequence",
            "supported catalog sequence",
        ),
        (
            before_current_vector.catalog_digest,
            qualification.catalog_digest,
            "before_current_vector.catalog_digest",
            "supported catalog",
        ),
        (
            before_current_vector.catalog_anchor_version,
            qualification.catalog_anchor_version,
            "before_current_vector.catalog_anchor_version",
            "catalog rollback anchor version",
        ),
        (
            before_current_vector.catalog_anchor_digest,
            qualification.catalog_anchor_digest,
            "before_current_vector.catalog_anchor_digest",
            "catalog rollback anchor",
        ),
        (
            before_current_vector.trust_root_digest,
            trust.root_set_digest,
            "before_current_vector.trust_root_digest",
            "qualification trust root",
        ),
        (
            before_current_vector.key_ring_sequence,
            trust.key_ring_sequence,
            "before_current_vector.key_ring_sequence",
            "qualification trust ring sequence",
        ),
        (
            before_current_vector.key_ring_digest,
            trust.key_ring_digest,
            "before_current_vector.key_ring_digest",
            "qualification trust ring",
        ),
        (
            before_current_vector.trust_anchor_version,
            trust.trust_anchor_version,
            "before_current_vector.trust_anchor_version",
            "trust rollback anchor version",
        ),
        (
            before_current_vector.trust_anchor_digest,
            trust.trust_anchor_digest,
            "before_current_vector.trust_anchor_digest",
            "trust rollback anchor",
        ),
    )
    for actual, expected, path, description in current_bindings:
        if actual != expected:
            fail(
                "STALE_AUTHORITY",
                path,
                f"{description} does not match the verified profile",
            )

    for value, path in (
        (checked_at, "checked_at"),
        (valid_until, "valid_until"),
    ):
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() is None
        ):
            fail(
                "TIME_INVALID",
                path,
                "expected a timezone-aware datetime",
            )
    normalized_checked_at = checked_at.astimezone(timezone.utc)
    normalized_valid_until = valid_until.astimezone(timezone.utc)
    if not (binding.bound_at <= normalized_checked_at < profile.expires_at):
        fail(
            "STALE_AUTHORITY",
            "checked_at",
            "evaluation time is outside the verified profile binding window",
        )
    if normalized_valid_until > profile.expires_at:
        fail(
            "STALE_AUTHORITY",
            "valid_until",
            "authorization window exceeds verified profile expiry",
        )
    expected_evidence_horizon = min(
        static_capability_context.inventory_closure.inventory.trust.freshness_expires_at,
        host_snapshot_anchor_binding.freshness_expires_at,
        binding.admission.policy.expires_at,
        profile.expires_at,
    )
    if before_current_vector.evidence_valid_until != expected_evidence_horizon:
        fail(
            "STALE_AUTHORITY",
            "before_current_vector.evidence_valid_until",
            (
                "authority evidence horizon does not exactly match the "
                "verified inventory, policy, and profile inputs"
            ),
        )


def _validate_closure_binding(
    capability_input: CapabilityInput,
    dependencies: ScopedCapabilityDependencies,
    before_current_vector: CurrentAuthorityVector,
    availability_read_set: AvailabilityReadSet,
    closure_facts: VerifiedClosureFacts,
    closure_result: DependencyClosureResult,
    snapshot_semantic_digest: str,
) -> None:
    if not isinstance(closure_facts, VerifiedClosureFacts):
        fail(
            "EVIDENCE_INCOMPLETE",
            "closure_facts",
            "expected verified closure facts",
        )
    if (
        not isinstance(closure_result, DependencyClosureResult)
        or not closure_result.success
        or closure_result.bundle is None
        or closure_result.reset_contract_set_digest is None
    ):
        fail(
            "EVIDENCE_INCOMPLETE",
            "closure_result",
            "a complete successful dependency/reset closure is required",
        )
    _binding(
        closure_result.facts_digest,
        closure_facts.facts_digest,
        "closure_result.facts_digest",
        "exact closure input",
    )
    _binding(
        closure_facts.snapshot_digest,
        dependencies.publisher_snapshot_digest,
        "closure_facts.snapshot_digest",
        "publisher snapshot",
    )
    _binding(
        closure_facts.inventory_verification_receipt_digest,
        before_current_vector.inventory_verification_receipt_digest,
        "closure_facts.inventory_verification_receipt_digest",
        "current inventory verification receipt",
    )
    if closure_facts.snapshot_epoch != capability_input.snapshot_epoch:
        fail(
            "STALE_AUTHORITY",
            "closure_facts.snapshot_epoch",
            "closure snapshot epoch does not match capability input",
        )
    _binding(
        closure_facts.request_provenance_digest,
        dependencies.request_digest,
        "closure_facts.request_provenance_digest",
        "request",
    )
    _binding(
        closure_facts.policy_provenance_digest,
        dependencies.policy_digest,
        "closure_facts.policy_provenance_digest",
        "closure policy",
    )
    _binding(
        closure_facts.inventory_verifier_identity_digest,
        dependencies.inventory_verifier_identity_digest,
        "closure_facts.inventory_verifier_identity_digest",
        "verifier identity",
    )
    _binding(
        snapshot_semantic_digest,
        dependencies.hardware_snapshot_semantic_digest,
        "inventory.snapshot_semantics.topology_digest",
        "replayed V3 inventory topology semantics",
    )
    _binding(
        closure_result.closure_request.request_digest,
        dependencies.closure_request_digest,
        "closure_result.closure_request",
        "approved closure roots and limits",
    )
    _binding(
        closure_result.closure_request.request_provenance_digest,
        dependencies.request_digest,
        "closure_result.closure_request.request_provenance_digest",
        "request",
    )
    _binding(
        closure_result.closure_request.policy_provenance_digest,
        dependencies.policy_digest,
        "closure_result.closure_request.policy_provenance_digest",
        "closure policy",
    )
    _binding(
        closure_result.bundle.bundle_hash,
        dependencies.dependency_bundle_digest,
        "closure_result.bundle.bundle_hash",
        "exact dependency bundle",
    )
    _binding(
        closure_result.bundle.semantic_digest,
        dependencies.dependency_bundle_semantic_digest,
        "closure_result.bundle.semantic_digest",
        "dependency bundle semantics",
    )
    _binding(
        closure_result.reset_contract_set_digest,
        dependencies.reset_contract_digest,
        "closure_result.reset_contract_set_digest",
        "resolved reset-contract set",
    )
    replayed = resolve_dependency_closure(
        facts=closure_facts,
        payload_device_uids=(closure_result.closure_request.payload_device_uids),
        limits=closure_result.closure_request.limits,
    )
    if replayed != closure_result:
        fail(
            "EVIDENCE_INCOMPLETE",
            "closure_result",
            (
                "closure result does not byte-equally match deterministic "
                "replay from the verified facts, roots, and limits"
            ),
        )
    availability_members = tuple(
        member.device_uid for member in availability_read_set.member_versions
    )
    if availability_members != closure_result.bundle.member_device_uids:
        fail(
            "STALE_AUTHORITY",
            "availability_read_set.member_versions",
            (
                "availability predicate members do not exactly match the "
                "verified dependency closure"
            ),
        )
    facts_by_uid = {device.device_uid: device for device in closure_facts.devices}
    for index, member in enumerate(availability_read_set.member_versions):
        device = facts_by_uid[member.device_uid]
        if (
            member.device_generation != device.device_generation
            or member.resource_version != device.resource_version
        ):
            fail(
                "STALE_AUTHORITY",
                f"availability_read_set.member_versions[{index}]",
                (
                    "availability member generation/resourceVersion does "
                    "not match the exact verified inventory record"
                ),
            )
    if capability_input.bundle != closure_result.dependency_bundle_reference():
        fail(
            "STALE_AUTHORITY",
            "capability_input.bundle",
            "bundle reference was not derived from the verified closure",
        )
    if capability_input.reset_contract != closure_result.reset_contract_reference():
        fail(
            "STALE_AUTHORITY",
            "capability_input.reset_contract",
            "reset reference was not derived from the verified closure",
        )


def evaluate_guarded_read(
    *,
    before_current_vector: CurrentAuthorityVector,
    capability_input: CapabilityInput,
    dependencies: ScopedCapabilityDependencies,
    after_current_vector: CurrentAuthorityVector,
    availability_read_set: AvailabilityReadSet,
    request_read_set: RequestReadSet,
    static_capability_context: VerifiedStaticCapabilityContext,
    host_snapshot_anchor_binding: VerifiedHostSnapshotAnchorBinding,
    checked_at: datetime,
    valid_until: datetime,
) -> GuardedCapabilityRead:
    """Return a decision only when the complete authority vector stayed fixed.

    All arguments are immutable values.  Supplying the after vector and trusted
    checked-at time is deliberately explicit: an adapter may fetch them using
    linearizable authority reads and a secure clock, but this portable core
    never receives an I/O function or performs those reads itself.
    """

    _validate_static_capability_context(
        static_capability_context,
        before_current_vector,
    )
    inventory_closure = static_capability_context.inventory_closure
    static_admission_context = inventory_closure.admission
    closure_facts = inventory_closure.facts
    closure_result = inventory_closure.result
    _validate_host_snapshot_anchor_binding(
        binding=host_snapshot_anchor_binding,
        inventory_closure=inventory_closure,
        before_current_vector=before_current_vector,
        checked_at=checked_at,
        valid_until=valid_until,
    )
    _validate_static_request_binding(
        capability_input=capability_input,
        dependencies=dependencies,
        before_current_vector=before_current_vector,
        request_read_set=request_read_set,
        static_admission_context=static_admission_context,
        closure_result=closure_result,
        valid_until=valid_until,
    )
    _validate_qualification_binding(
        capability_input=capability_input,
        dependencies=dependencies,
        before_current_vector=before_current_vector,
        static_capability_context=static_capability_context,
        host_snapshot_anchor_binding=host_snapshot_anchor_binding,
        checked_at=checked_at,
        valid_until=valid_until,
    )
    _validate_factory_capability_gates(
        capability_input,
        static_capability_context,
    )
    _validate_selected_bindings(capability_input, dependencies)
    _validate_before_current(dependencies, before_current_vector)
    _validate_availability_gate(
        capability_input,
        availability_read_set,
    )
    _validate_closure_binding(
        capability_input,
        dependencies,
        before_current_vector,
        availability_read_set,
        closure_facts,
        closure_result,
        inventory_closure.inventory.snapshot_semantics.topology_digest,
    )

    evaluation = evaluate_capability(capability_input)
    authorization_blockers = tuple(
        sorted(
            _COMPONENT_AUTHORIZATION_BLOCKERS
            | set(
                static_capability_context.qualification_binding.authorization_blockers
            ),
            key=canonical_json_bytes,
        )
    )
    authority_disposition = CapabilityAuthorityDisposition(
        static_capability_context_digest=(
            static_capability_context.context_digest
        ),
        hardware_premise_digest=(
            static_capability_context.hardware_premise_digest
        ),
        hardware_premise_authority_boundary=(
            static_capability_context.hardware_premise_authority_boundary
        ),
        resource_plan_context_digest=(
            static_capability_context.resource_plan.context_digest
        ),
        resource_plan_hash=static_capability_context.resource_plan_hash,
        resource_plan_authority_boundary=(
            static_capability_context.resource_plan.authority_boundary
        ),
        qualification_binding_context_digest=(
            static_capability_context.qualification_binding.context_digest
        ),
        qualification_authority_boundary=(
            static_capability_context.qualification_binding.authority_boundary
        ),
        host_snapshot_anchor_binding_digest=(
            host_snapshot_anchor_binding.binding_digest
        ),
        host_snapshot_anchor_authority_boundary=(
            host_snapshot_anchor_binding.authority_boundary
        ),
        authorization_blockers=authorization_blockers,
    )
    authorization = _bind_authorization(
        decision_digest=evaluation.decision.decision_hash,
        dependencies=dependencies,
        current=before_current_vector,
        availability_read_set=availability_read_set,
        request_read_set=request_read_set,
        authority_disposition=authority_disposition,
        evaluated_at=checked_at,
        valid_until=valid_until,
    )

    # This is intentionally the final check before constructing the response.
    assert_current(
        authorization,
        after_current_vector,
        at=checked_at,
        expected_decision_digest=evaluation.decision.decision_hash,
        dependencies=dependencies,
    )
    return GuardedCapabilityRead(
        evaluation=evaluation,
        authorization=authorization,
    )


__all__ = ["GuardedCapabilityRead", "evaluate_guarded_read"]
