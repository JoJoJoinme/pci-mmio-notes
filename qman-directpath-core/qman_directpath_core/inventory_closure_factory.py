"""Typed bridge from verified portable inventory to closure facts.

Only values retained in ``VerifiedInventoryContext`` and
``VerifiedStaticAdmissionContext`` enter this projection.  The caller cannot
supply roots, closure limits, request/policy provenance, a snapshot digest,
inventory-verification receipt, or verifier identity as independent values.

The verifier identity is the identity of the fixed, schema-bound component
algorithm.  It is not binary, build, product, or runtime attestation.  The
inventory-verification receipt closes the verifier's exact supplied inputs; it
does not prove repository linearizability, publication CAS, or side effects.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any

from .admission import VerifiedStaticAdmissionContext
from .canonical import canonical_json_bytes, sha256_digest
from .capability import GateAssessment, Reason
from .closure import (
    DependencyClosureResult,
    DependencyAction,
    DependencyKind,
    FactState,
    ResetMethod,
    VerifiedClosureFacts,
    VerifiedDependencyDomain,
    VerifiedDependencyEdge,
    VerifiedDeviceFacts,
    VerifiedResetContract,
    resolve_dependency_closure,
)
from .errors import require
from .inventory import VerifiedInventoryContext
from ._verified import FactoryVerified, require_factory_verified


class ClosureProjectionGapCode(str, Enum):
    """Historical closed gap codes retained for assessment compatibility."""

    INVENTORY_VERIFICATION_RECEIPT_UNAVAILABLE = (
        "INVENTORY_VERIFICATION_RECEIPT_UNAVAILABLE"
    )
    VERIFIER_IDENTITY_UNAVAILABLE = "VERIFIER_IDENTITY_UNAVAILABLE"
    IOMMU_DOMAIN_MAPPING_AMBIGUOUS = "IOMMU_DOMAIN_MAPPING_AMBIGUOUS"
    DEPENDENCY_DOMAIN_FACT_MISSING = "DEPENDENCY_DOMAIN_FACT_MISSING"
    DOMAIN_ACTION_KIND_MISSING = "DOMAIN_ACTION_KIND_MISSING"


@dataclass(frozen=True, slots=True)
class ClosureProjectionGap:
    """One closed assessment failure.

    A V3 DeviceRecord that passed ``verify_inventory_context`` supplies every
    required field, so the successful projection path emits no instances.
    """

    code: ClosureProjectionGapCode
    path: str
    message: str
    device_uid: str | None = None
    dependency_kind: DependencyKind | None = None
    provenance_digests: tuple[str, ...] = ()

    def to_subject(self) -> dict[str, object]:
        return {
            "code": self.code.value,
            "path": self.path,
            "message": self.message,
            "deviceUidOrNull": self.device_uid,
            "dependencyKindOrNull": (
                None if self.dependency_kind is None else self.dependency_kind.value
            ),
            "provenanceDigests": list(self.provenance_digests),
        }


@dataclass(frozen=True, slots=True)
class VerifiedPhysicalIsolationMembership:
    """Compatibility view of one retained physical-isolation domain."""

    device_uid: str
    state: FactState
    member_device_uids: tuple[str, ...]
    provenance_digest: str
    closure_domain_or_none: VerifiedDependencyDomain | None

    def to_subject(self) -> dict[str, object]:
        return {
            "deviceUid": self.device_uid,
            "state": self.state.value,
            "memberDeviceUids": list(self.member_device_uids),
            "provenanceDigest": self.provenance_digest,
            "closureDomainOrNull": (
                None
                if self.closure_domain_or_none is None
                else self.closure_domain_or_none.to_subject()
            ),
        }


@dataclass(frozen=True, slots=True)
class VerifiedDeviceResetProjection:
    """Compatibility view of one retained reset contract."""

    device_uid: str
    reset_contract: VerifiedResetContract

    def to_subject(self) -> dict[str, object]:
        return {
            "deviceUid": self.device_uid,
            "resetContract": self.reset_contract.to_subject(),
        }


@dataclass(frozen=True, slots=True)
class InventoryClosureProjectionAssessment:
    """Immutable successful projection of one verified V3 inventory."""

    snapshot_epoch: int
    snapshot_digest: str
    inventory_verification_receipt_digest: str
    inventory_verifier_identity_digest: str
    request_provenance_digest: str
    policy_provenance_digest: str
    device_facts: tuple[VerifiedDeviceFacts, ...]
    gaps: tuple[ClosureProjectionGap, ...] = ()

    @property
    def complete(self) -> bool:
        return not self.gaps

    @property
    def verification_receipt_digest(self) -> str:
        """Compatibility spelling for the closed receipt digest."""

        return self.inventory_verification_receipt_digest

    @property
    def verifier_identity_digest(self) -> str:
        """Compatibility spelling for the component algorithm identity."""

        return self.inventory_verifier_identity_digest

    def to_subject(self) -> dict[str, object]:
        return {
            "subjectType": "INVENTORY_CLOSURE_PROJECTION_ASSESSMENT",
            "schemaVersion": 2,
            "snapshotEpoch": self.snapshot_epoch,
            "snapshotDigest": self.snapshot_digest,
            "inventoryVerificationReceiptDigest": (
                self.inventory_verification_receipt_digest
            ),
            "inventoryVerifierIdentityDigest": (
                self.inventory_verifier_identity_digest
            ),
            "requestProvenanceDigest": self.request_provenance_digest,
            "policyProvenanceDigest": self.policy_provenance_digest,
            "deviceFacts": [item.to_subject() for item in self.device_facts],
            "gaps": [gap.to_subject() for gap in self.gaps],
        }

    @property
    def assessment_digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_subject()))


@dataclass(frozen=True, slots=True, init=False)
class VerifiedStaticInventoryClosureContext(FactoryVerified):
    """Exact typed inputs and deterministic closure result for one request."""

    inventory: VerifiedInventoryContext
    admission: VerifiedStaticAdmissionContext
    facts: VerifiedClosureFacts
    result: DependencyClosureResult
    hardware_premise: VerifiedPayloadHardwarePremise


HARDWARE_PREMISE_AUTHORITY_BOUNDARY = (
    "COMPONENT_VERIFIED_INVENTORY_PREMISE_ONLY"
)
HARDWARE_PREMISE_PRODUCT_AUTHORIZED = False
_ENDPOINT_PORT_TYPES = frozenset(
    {
        "ENDPOINT",
        "LEGACY_ENDPOINT",
        "ROOT_COMPLEX_INTEGRATED_ENDPOINT",
    }
)


def _gate_wire(gate: GateAssessment) -> dict[str, object]:
    return {
        "state": gate.state.value,
        "reasons": [reason.to_wire() for reason in gate.reasons],
    }


def _freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _freeze_json(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


@dataclass(frozen=True, slots=True, init=False)
class VerifiedPayloadHardwarePremise(FactoryVerified):
    """Factory-only C00 structure/reset premise for the selected payloads.

    A positive component gate proves deterministic replay from the supplied,
    signed V3 inventory only.  ``product_authorized`` remains false until a
    Qman product collector, publication path, repository currentness proof,
    resource planner and release evidence are independently mapped.
    """

    payload_device_uids: tuple[str, ...]
    device_premises: tuple[Mapping[str, Any], ...]
    owner_activation_device_uids: tuple[str, ...]
    owner_activation_premises: tuple[Mapping[str, Any], ...]
    hardware_gate: GateAssessment
    technical_gate: GateAssessment
    admin_gate: GateAssessment
    owner_active_gate: GateAssessment
    authority_boundary: str
    product_authorized: bool
    premise_digest: str

    def to_subject(self) -> dict[str, object]:
        return {
            "subjectType": "VERIFIED_PAYLOAD_HARDWARE_PREMISE",
            "schemaVersion": 1,
            "payloadDeviceUids": list(self.payload_device_uids),
            "devicePremises": [
                _thaw_json(premise) for premise in self.device_premises
            ],
            "ownerActivationDeviceUids": list(
                self.owner_activation_device_uids
            ),
            "ownerActivationPremises": [
                _thaw_json(premise)
                for premise in self.owner_activation_premises
            ],
            "hardwareGate": _gate_wire(self.hardware_gate),
            "technicalGate": _gate_wire(self.technical_gate),
            "adminGate": _gate_wire(self.admin_gate),
            "ownerActiveGate": _gate_wire(self.owner_active_gate),
            "authorityBoundary": self.authority_boundary,
            "productAuthorized": self.product_authorized,
            "premiseDigest": self.premise_digest,
        }


def _age_micros(inventory: VerifiedInventoryContext) -> int:
    age = inventory.verified_at - inventory.captured_at
    return (age.days * 86_400 + age.seconds) * 1_000_000 + age.microseconds


def _bind_inventory_admission(
    inventory: VerifiedInventoryContext,
    admission: VerifiedStaticAdmissionContext,
) -> None:
    require_factory_verified(
        inventory,
        VerifiedInventoryContext,
        code="CLOSURE_PROJECTION_INPUT_INVALID",
        path="inventory",
        message="inventory must come from verify_inventory_context",
    )
    require_factory_verified(
        admission,
        VerifiedStaticAdmissionContext,
        code="CLOSURE_PROJECTION_INPUT_INVALID",
        path="admission",
        message="admission must come from bind_static_request_policy",
    )
    request = admission.request
    require(
        inventory.host_id == request.host_id,
        "STATIC_ADMISSION_INVENTORY_MISMATCH",
        "admission.request.hostId",
        "request host does not match the verified inventory host",
    )
    require(
        inventory.policy_hash == admission.policy.policy_hash,
        "STATIC_ADMISSION_INVENTORY_MISMATCH",
        "inventory.policyHash",
        "HostSnapshot policyHash does not match the verified policy",
    )
    require(
        _age_micros(inventory) <= request.maximum_age_micros,
        "HOST_SNAPSHOT_STALE",
        "inventory.capturedAt",
        "verified inventory exceeds request maximumAgeMicros",
    )

    constraint = request.canonical_request["snapshotConstraint"]
    if constraint["mode"] == "PINNED_CURRENT_SNAPSHOT":
        binding = constraint["binding"]
        expected = {
            "hostId": inventory.host_id,
            "kernelBootId": inventory.kernel_boot_id,
            "hostEpoch": inventory.host_epoch,
            "agentGeneration": inventory.agent_generation,
            "hostAuthorityResourceVersion": (
                inventory.snapshot_authority_resource_version
            ),
            "snapshotEpoch": inventory.snapshot_epoch,
            "snapshotContentHash": inventory.snapshot_content_hash,
        }
        require(
            canonical_json_bytes(binding) == canonical_json_bytes(expected),
            "STATIC_ADMISSION_INVENTORY_MISMATCH",
            "admission.request.snapshotConstraint.binding",
            "pinned snapshot binding does not exactly match the inventory",
        )

    for index, member in enumerate(request.canonical_request["selector"]["members"]):
        path = f"admission.request.selector.members[{index}]"
        record = inventory.device(member["deviceUid"])
        require(
            member["identityFingerprint"] == record.identity.identity_fingerprint,
            "STATIC_DEVICE_IDENTITY_DRIFT",
            f"{path}.identityFingerprint",
            "static identity fingerprint changed",
        )
        require(
            canonical_json_bytes(member["expectedPhysicalPathProvider"])
            == canonical_json_bytes(record.document["physicalPathProvider"])
            and member["expectedPhysicalPath"] == record.document["physicalPath"],
            "STATIC_DEVICE_LOCATION_DRIFT",
            f"{path}.expectedPhysicalPath",
            "static physical path/provider changed",
        )
        require(
            member["expectedCurrentBdf"] == record.current_bdf,
            "STATIC_DEVICE_LOCATION_DRIFT",
            f"{path}.expectedCurrentBdf",
            "static current BDF changed",
        )


def _dependency_edge(document: Mapping[str, Any]) -> VerifiedDependencyEdge:
    action = document["requiredActionOrNull"]
    return VerifiedDependencyEdge(
        target_device_uid=document["targetDeviceUid"],
        action_state=FactState(document["actionState"]),
        required_action=(None if action is None else DependencyAction(action)),
        provenance_digest=document["provenanceDigest"],
    )


def _dependency_domain(document: Mapping[str, Any]) -> VerifiedDependencyDomain:
    return VerifiedDependencyDomain(
        kind=DependencyKind(document["kind"]),
        state=FactState(document["state"]),
        provenance_digest=document["provenanceDigest"],
        edges=tuple(_dependency_edge(edge) for edge in document["edges"]),
    )


def _reset_contract(document: Mapping[str, Any]) -> VerifiedResetContract:
    method = document["selectedMethodOrNull"]
    return VerifiedResetContract(
        state=FactState(document["state"]),
        supported=document["supported"],
        selected_method=(None if method is None else ResetMethod(method)),
        affected_device_uids=tuple(document["resetAffectedSet"]),
        contract_digest=document["contractDigest"],
        provenance_digest=document["provenanceDigest"],
    )


def _device_facts(
    *,
    document: Mapping[str, Any],
    device_uid: str,
    device_record_digest: str,
) -> VerifiedDeviceFacts:
    generations = document["generations"]
    return VerifiedDeviceFacts(
        device_uid=device_uid,
        device_record_digest=device_record_digest,
        device_generation=generations["deviceGeneration"],
        resource_version=generations["resourceVersion"],
        domains=tuple(
            _dependency_domain(domain) for domain in document["dependencyDomains"]
        ),
        reset_contract=_reset_contract(document["resetContract"]),
    )


def _capability_reason(code: str, device_uid: str) -> Reason:
    return Reason(
        code=code,
        stage="capability",
        devices=(device_uid,),
    )


def _owner_reason(code: str, device_uid: str) -> Reason:
    return Reason(
        code=code,
        stage="owner",
        devices=(device_uid,),
    )


def _policy_reason(code: str, device_uid: str) -> Reason:
    return Reason(
        code=code,
        stage="policy",
        devices=(device_uid,),
    )


def _extend_unique_reasons(
    target: list[Reason],
    values: tuple[Reason, ...],
) -> None:
    seen = {
        (reason.stage, reason.code, reason.devices)
        for reason in target
    }
    for reason in values:
        key = (reason.stage, reason.code, reason.devices)
        if key not in seen:
            target.append(reason)
            seen.add(key)


def _derive_payload_hardware_premise(
    inventory: VerifiedInventoryContext,
    admission: VerifiedStaticAdmissionContext,
    result: DependencyClosureResult,
) -> VerifiedPayloadHardwarePremise:
    payload_uids = admission.closure_request.payload_device_uids
    device_premises: list[dict[str, Any]] = []
    owner_activation_premises: list[dict[str, Any]] = []
    hardware_reasons: list[Reason] = []
    admin_reasons: list[Reason] = []
    owner_reasons: list[Reason] = []
    for device_uid in payload_uids:
        verified = inventory.device(device_uid)
        document = verified.document
        structure = verified.pci_config_facts.structure_fact
        flr = verified.pci_config_facts.flr_fact
        iommu = document["iommuProvider"]
        physical = document["physicalIsolationDomain"]
        interrupts = document["interrupts"]
        reset = document["resetContract"]
        owner = document["owner"]
        device_premises.append(
            {
                "deviceUid": device_uid,
                "deviceRecordHash": verified.device_record_hash,
                "structuralRole": document["role"]["structuralRole"],
                "pciStructureFactDigest": (
                    verified.pci_config_facts.structure_fact_digest
                ),
                "headerLayout": structure["headerLayout"],
                "multifunctionOrNull": structure["multifunctionOrNull"],
                "pcieCapabilityState": structure["pcieCapabilityState"],
                "pcieDevicePortTypeOrNull": structure[
                    "pcieDevicePortTypeOrNull"
                ],
                "pciFlrCapabilityFactDigest": (
                    verified.pci_config_facts.flr_fact_digest
                ),
                "pciFlrCapabilityState": flr["state"],
                "functionLevelResetCapableOrNull": flr[
                    "functionLevelResetCapableOrNull"
                ],
                "dmaIsolationMode": iommu["dmaIsolationMode"],
                "iommuBackendCapability": iommu["backendCapability"],
                "kernelIommuGroup": list(iommu["kernelIommuGroup"]),
                "physicalIsolationState": physical["state"],
                "physicalIsolationMembers": list(
                    physical["memberDeviceUids"]
                ),
                "interruptRemapping": interrupts["interruptRemapping"],
                "resetState": reset["state"],
                "resetSupported": reset["supported"],
                "selectedResetMethodOrNull": reset["selectedMethodOrNull"],
                "resetAffectedSet": list(reset["resetAffectedSet"]),
                "resetContractDigest": reset["contractDigest"],
                "adminEnabled": owner["adminEnabled"],
                "desiredOwner": owner["desiredOwner"],
                "effectiveOwner": owner["effectiveOwner"],
                "hostActive": owner["hostActive"],
                "activationDisposition": owner["activationDisposition"],
                "driverOrNull": owner["driverOrNull"],
                "ownerActivationGroup": list(owner["ownerActivationGroup"]),
                "exclusiveAttachGroup": owner["exclusiveAttachGroup"],
                "ownerProvenanceDigest": owner["provenanceDigest"],
            }
        )
        if (
            document["role"]["structuralRole"] != "ENDPOINT_PAYLOAD"
            or structure["state"] != "KNOWN"
            or structure["headerLayout"] != "TYPE_0"
            or structure["pcieCapabilityState"] != "PRESENT"
            or structure["pcieDevicePortTypeOrNull"]
            not in _ENDPOINT_PORT_TYPES
        ):
            hardware_reasons.append(
                _capability_reason(
                    "HARDWARE_ROLE_NOT_ASSIGNABLE",
                    device_uid,
                )
            )
        if iommu["dmaIsolationMode"] == "NO_IOMMU":
            hardware_reasons.append(
                _capability_reason(
                    "DEVICE_NO_IOMMU_DMA_ISOLATION",
                    device_uid,
                )
            )
        elif (
            iommu["dmaIsolationMode"] != "IOMMU"
            or iommu["backendCapability"] in {"NONE", "UNKNOWN"}
            or verified.current_bdf not in iommu["kernelIommuGroup"]
        ):
            hardware_reasons.append(
                _capability_reason(
                    "DEVICE_IOMMU_BACKING_UNKNOWN",
                    device_uid,
                )
            )
        if (
            physical["state"] != "KNOWN"
            or device_uid not in physical["memberDeviceUids"]
        ):
            hardware_reasons.append(
                _capability_reason(
                    "PHYSICAL_ISOLATION_DOMAIN_UNKNOWN",
                    device_uid,
                )
            )
        if interrupts["interruptRemapping"] != "PRESENT":
            hardware_reasons.append(
                _capability_reason(
                    "INTERRUPT_REMAP_MISSING",
                    device_uid,
                )
            )
        if reset["state"] != "KNOWN":
            hardware_reasons.append(
                _capability_reason("RESET_DOMAIN_UNVERIFIED", device_uid)
            )
        elif not reset["supported"]:
            hardware_reasons.append(
                _capability_reason("RESET_NOT_SUPPORTED", device_uid)
            )
        elif (
            reset["selectedMethodOrNull"] is None
            or device_uid not in reset["resetAffectedSet"]
        ):
            hardware_reasons.append(
                _capability_reason("RESET_DOMAIN_UNVERIFIED", device_uid)
            )
        if not owner["adminEnabled"]:
            admin_reasons.append(
                _policy_reason("ADMIN_DISABLED", device_uid)
            )
    owner_activation_uids = (
        result.bundle.owner_activation_group
        if result.success and result.bundle is not None
        else payload_uids
    )
    for device_uid in owner_activation_uids:
        owner = inventory.device(device_uid).document["owner"]
        owner_activation_premises.append(
            {
                "deviceUid": device_uid,
                "adminEnabled": owner["adminEnabled"],
                "desiredOwner": owner["desiredOwner"],
                "effectiveOwner": owner["effectiveOwner"],
                "hostActive": owner["hostActive"],
                "activationDisposition": owner["activationDisposition"],
                "driverOrNull": owner["driverOrNull"],
                "ownerActivationGroup": list(
                    owner["ownerActivationGroup"]
                ),
                "exclusiveAttachGroup": owner["exclusiveAttachGroup"],
                "ownerProvenanceDigest": owner["provenanceDigest"],
            }
        )
        if (
            not owner["hostActive"]
            or owner["desiredOwner"] != "PASSTHROUGH"
            or owner["effectiveOwner"] != "PASSTHROUGH"
            or owner["activationDisposition"] != "ALREADY_ACTIVE"
        ):
            owner_reasons.append(
                _owner_reason("HOST_ACTIVATION_REQUIRED", device_uid)
            )
        if tuple(owner["ownerActivationGroup"]) != owner_activation_uids:
            owner_reasons.append(
                _owner_reason(
                    "ACTIVATION_OBSERVED_STATE_MISMATCH",
                    device_uid,
                )
            )

    if not result.success:
        _extend_unique_reasons(hardware_reasons, result.reasons)
    hardware_gate = (
        GateAssessment.yes()
        if not hardware_reasons
        else GateAssessment.no(*hardware_reasons)
    )
    technical_reasons = list(hardware_gate.reasons)
    if not result.success:
        _extend_unique_reasons(technical_reasons, result.reasons)
    technical_gate = (
        GateAssessment.yes()
        if not technical_reasons
        else GateAssessment.no(*technical_reasons)
    )
    admin_gate = (
        GateAssessment.yes()
        if not admin_reasons
        else GateAssessment.no(*admin_reasons)
    )
    owner_active_gate = (
        GateAssessment.yes()
        if not owner_reasons
        else GateAssessment.no(*owner_reasons)
    )
    subject = {
        "subjectType": "VERIFIED_PAYLOAD_HARDWARE_PREMISE",
        "schemaVersion": 1,
        "payloadDeviceUids": list(payload_uids),
        "devicePremises": device_premises,
        "ownerActivationDeviceUids": list(owner_activation_uids),
        "ownerActivationPremises": owner_activation_premises,
        "hardwareGate": _gate_wire(hardware_gate),
        "technicalGate": _gate_wire(technical_gate),
        "adminGate": _gate_wire(admin_gate),
        "ownerActiveGate": _gate_wire(owner_active_gate),
        "authorityBoundary": HARDWARE_PREMISE_AUTHORITY_BOUNDARY,
        "productAuthorized": HARDWARE_PREMISE_PRODUCT_AUTHORIZED,
        "premiseDigest": None,
    }
    premise_digest = sha256_digest(canonical_json_bytes(subject))
    return VerifiedPayloadHardwarePremise._construct(
        payload_device_uids=payload_uids,
        device_premises=tuple(
            _freeze_json(premise) for premise in device_premises
        ),
        owner_activation_device_uids=owner_activation_uids,
        owner_activation_premises=tuple(
            _freeze_json(premise)
            for premise in owner_activation_premises
        ),
        hardware_gate=hardware_gate,
        technical_gate=technical_gate,
        admin_gate=admin_gate,
        owner_active_gate=owner_active_gate,
        authority_boundary=HARDWARE_PREMISE_AUTHORITY_BOUNDARY,
        product_authorized=HARDWARE_PREMISE_PRODUCT_AUTHORIZED,
        premise_digest=premise_digest,
    )


def assess_inventory_closure_projection(
    inventory: VerifiedInventoryContext,
    admission: VerifiedStaticAdmissionContext,
) -> InventoryClosureProjectionAssessment:
    """Project every verified V3 DeviceRecord without inventing domain facts."""

    _bind_inventory_admission(inventory, admission)
    request_digest = admission.request.request_hash
    policy_digest = admission.policy.policy_hash
    devices = tuple(
        sorted(
            (
                _device_facts(
                    document=record.document,
                    device_uid=record.device_uid,
                    device_record_digest=record.device_record_hash,
                )
                for record in inventory.device_records
            ),
            key=lambda device: canonical_json_bytes(device.device_uid),
        )
    )
    return InventoryClosureProjectionAssessment(
        snapshot_epoch=inventory.snapshot_epoch,
        snapshot_digest=inventory.snapshot_content_hash,
        inventory_verification_receipt_digest=(
            inventory.inventory_verification_receipt_digest
        ),
        inventory_verifier_identity_digest=(
            inventory.inventory_verifier_identity_digest
        ),
        request_provenance_digest=request_digest,
        policy_provenance_digest=policy_digest,
        device_facts=devices,
    )


def project_verified_closure_facts(
    inventory: VerifiedInventoryContext,
    admission: VerifiedStaticAdmissionContext,
) -> VerifiedClosureFacts:
    """Construct the resolver input from a verified inventory context only."""

    assessment = assess_inventory_closure_projection(
        inventory,
        admission,
    )
    require(
        assessment.complete,
        "CLOSURE_PROJECTION_INCOMPLETE",
        "inventory.closureProjection",
        "verified inventory projection contains a closed gap",
    )
    return VerifiedClosureFacts(
        snapshot_epoch=assessment.snapshot_epoch,
        snapshot_digest=assessment.snapshot_digest,
        inventory_verification_receipt_digest=(
            assessment.inventory_verification_receipt_digest
        ),
        inventory_verifier_identity_digest=(
            assessment.inventory_verifier_identity_digest
        ),
        request_provenance_digest=assessment.request_provenance_digest,
        policy_provenance_digest=assessment.policy_provenance_digest,
        devices=assessment.device_facts,
    )


def resolve_static_inventory_closure(
    inventory: VerifiedInventoryContext,
    admission: VerifiedStaticAdmissionContext,
) -> VerifiedStaticInventoryClosureContext:
    """Project and resolve using only typed roots, policy limits and facts."""

    facts = project_verified_closure_facts(inventory, admission)
    result = resolve_dependency_closure(
        facts=facts,
        payload_device_uids=(admission.closure_request.payload_device_uids),
        limits=admission.closure_request.limits,
    )
    require(
        result.closure_request == admission.closure_request,
        "CLOSURE_PROJECTION_INCOMPLETE",
        "inventory.closureResult.closureRequest",
        "resolver did not retain the exact typed admission closure request",
    )
    hardware_premise = _derive_payload_hardware_premise(
        inventory,
        admission,
        result,
    )
    return VerifiedStaticInventoryClosureContext._construct(
        inventory=inventory,
        admission=admission,
        facts=facts,
        result=result,
        hardware_premise=hardware_premise,
    )


__all__ = [
    "ClosureProjectionGap",
    "ClosureProjectionGapCode",
    "InventoryClosureProjectionAssessment",
    "VerifiedDeviceResetProjection",
    "VerifiedPhysicalIsolationMembership",
    "VerifiedStaticInventoryClosureContext",
    "VerifiedPayloadHardwarePremise",
    "HARDWARE_PREMISE_AUTHORITY_BOUNDARY",
    "HARDWARE_PREMISE_PRODUCT_AUTHORIZED",
    "assess_inventory_closure_projection",
    "project_verified_closure_facts",
    "resolve_static_inventory_closure",
]
