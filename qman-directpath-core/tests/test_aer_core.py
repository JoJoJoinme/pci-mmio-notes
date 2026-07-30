from __future__ import annotations

import copy
from dataclasses import fields, replace
from datetime import datetime, timedelta, timezone
import unittest

from qman_directpath_core.aer_admission import (
    AER_ADMISSION_ASSESSMENT_DOMAIN,
    AER_ADMISSION_CURRENT_RECEIPT_DOMAIN,
    AER_ADMISSION_MAX_RECEIPT_BYTES,
    AER_ADMISSION_MAX_RUNTIME_GATE_TTL,
    AerAdmissionCurrentRequest,
    AerAdmissionDenyReason,
    AerAdmissionExpectation,
    AerRuntimeGate,
    VerifiedStructuralAerAdmissionCurrentReceipt,
    evaluate_aer_admission,
    prepare_aer_admission_current_request,
    verify_structural_aer_admission_current_receipt,
)
from qman_directpath_core.aer_evidence import (
    AER_AUTHORITY_BOUNDARY,
    AER_E4_CASE_RESULTS_DOMAIN,
    AER_E4_REPLAY_RECEIPT_DOMAIN,
    AER_EVIDENCE_DIGEST_DOMAIN,
    AER_MAX_DOCUMENT_BYTES,
    AER_MAX_E4_EVIDENCE_HASHES,
    AER_MAX_SOURCE_HASHES,
    AER_QUALIFICATION_DIGEST_DOMAIN,
    AER_REQUIRED_CASE_IDS,
    AerDimension,
    AerE4ReplayRequest,
    AerEvidenceClassification,
    AerQualificationResult,
    VerifiedAerEvidence,
    VerifiedAerE4ReplayReceipt,
    VerifiedAerQualification,
    prepare_aer_e4_replay_request,
    verify_aer_evidence,
    verify_aer_qualification,
)
from qman_directpath_core.aer_policy import (
    AER_CONFIG_LAYOUT_DIGEST_DOMAIN,
    AER_POLICY_DIGEST_DOMAIN,
    AerField,
    AerFunctionRole,
    CORRECTABLE_ERROR_ALLOW_MASK,
    FILTER_BEFORE_VFIO,
    PhysicalConfigWrite,
    ReadLaneDisposition,
    VerifiedAerPolicy,
    VerifiedAerConfigLayout,
    VerifiedExecutableAerWritePlan,
    VerifiedGuestConfigWriteClassification,
    VerifiedGuestConfigWritePlan,
    VerifiedGuestProjectedAerSnapshot,
    WriteDenyReason,
    consume_executable_aer_write,
    plan_guest_config_write,
    project_guest_aer_snapshot,
    project_guest_config_read,
    project_guest_read,
    project_guest_root_source_read,
    project_hidden_ext_cap_chain,
    require_current_aer_layout,
    require_pre_vfio_plan,
    verify_aer_config_layout,
    verify_aer_policy,
)
from qman_directpath_core.aer_reference_model import (
    AerReferenceModel,
    CorrectableRouteControl,
    LifecyclePhase,
    Observation,
    PhysicalCorrectableState,
    ROOT_CORRECTABLE_RECEIVED,
    ROOT_CORRECTABLE_STATUS_MASK,
    ROOT_MULTIPLE_CORRECTABLE_RECEIVED,
)
from qman_directpath_core.canonical import (
    canonical_json_bytes,
    load_canonical_json,
    sha256_digest,
)
from qman_directpath_core.errors import DirectPathVerificationError


CORRECTABLE_BITS = (0x1, 0x40, 0x80, 0x100, 0x1000, 0x2000, 0x4000, 0x8000)
NOW = datetime(2026, 7, 29, 1, 0, tzinfo=timezone.utc)


def _hash(label: str) -> str:
    return sha256_digest(label.encode("ascii"))


def _policy_document(
    *,
    header: str = "VISIBLE",
    body: str = "VISIBLE",
    hidden_read: str = "ZERO",
    physical_writes: bool = True,
) -> dict:
    shadow_writes = not physical_writes and hidden_read == "SHADOW"
    status_write = (
        "FILTERED_W1C" if physical_writes or shadow_writes else "DENY"
    )
    field_specs = {
        "PCIE_DEVICE_CONTROL": ("PHYSICAL", 0x1, "DENY", 0, 0),
        "PCIE_DEVICE_STATUS": (
            (
                "PHYSICAL"
                if physical_writes
                else ("SHADOW" if shadow_writes else "ZERO")
            ),
            0x1,
            status_write,
            0x1 if physical_writes else 0,
            0x1 if shadow_writes else 0,
        ),
        "CORRECTABLE_ERROR_STATUS": (
            "PHYSICAL",
            CORRECTABLE_ERROR_ALLOW_MASK,
            status_write,
            CORRECTABLE_ERROR_ALLOW_MASK if physical_writes else 0,
            CORRECTABLE_ERROR_ALLOW_MASK if shadow_writes else 0,
        ),
        "CORRECTABLE_ERROR_MASK": (
            "PHYSICAL",
            CORRECTABLE_ERROR_ALLOW_MASK,
            "DENY",
            0,
            0,
        ),
        "ROOT_ERROR_COMMAND": ("PHYSICAL", 0x1, "DENY", 0, 0),
        "ROOT_ERROR_STATUS": (
            "PHYSICAL",
            ROOT_CORRECTABLE_STATUS_MASK,
            status_write,
            ROOT_CORRECTABLE_STATUS_MASK if physical_writes else 0,
            ROOT_CORRECTABLE_STATUS_MASK if shadow_writes else 0,
        ),
        "ERROR_SOURCE_ID": ("PHYSICAL", 0xFFFF, "DENY", 0, 0),
    }
    document = {
        "subjectType": "QMAN_AER_POLICY",
        "schemaVersion": 1,
        "policyId": "aer-policy-test",
        "correctableOnly": True,
        "extendedCapability": {
            "headerExposure": header,
            "bodyExposure": body,
            "hiddenBodyReadProjection": hidden_read,
        },
        "writePipeline": FILTER_BEFORE_VFIO,
        "unknownFieldAction": "DENY",
        "fields": {
            name: {
                "readProjection": read,
                "guestReadAllowMask": read_mask,
                "writeDisposition": write,
                "physicalW1cAllowMask": physical,
                "shadowW1cMask": shadow,
            }
            for name, (
                read,
                read_mask,
                write,
                physical,
                shadow,
            ) in field_specs.items()
        },
        "aerPolicyDigest": None,
    }
    document["aerPolicyDigest"] = sha256_digest(
        AER_POLICY_DIGEST_DOMAIN + canonical_json_bytes(document)
    )
    return document


def _layout(
    *,
    role: AerFunctionRole = AerFunctionRole.ENDPOINT,
    aer_offset: int = 0x180,
    pcie_offset: int = 0x70,
) -> VerifiedAerConfigLayout:
    document = {
        "subjectType": "QMAN_AER_CONFIG_LAYOUT",
        "schemaVersion": 1,
        "deviceIdentityDigest": _hash("device"),
        "bdf": (
            "0000:01:00.1"
            if role is AerFunctionRole.ENDPOINT
            else "0000:00:08.0"
        ),
        "hostBootId": "boot-a",
        "assignmentId": "assignment-a",
        "leaseGeneration": 7,
        "ownerEpoch": 11,
        "pcieCapabilityOffset": pcie_offset,
        "pcieCapabilityHeader": 0x0010,
        "pcieCapabilitiesRegister": (
            0x0000 if role is AerFunctionRole.ENDPOINT else 0x0040
        ),
        "aerCapabilityOffset": aer_offset,
        "aerCapabilityHeader": 0x00010001,
        "aerPredecessorOffsetOrNull": 0x140,
        "aerPredecessorHeaderOrNull": (
            (aer_offset << 20) | 0x00010010
        ),
        "layoutDigest": None,
    }
    document["layoutDigest"] = sha256_digest(
        AER_CONFIG_LAYOUT_DIGEST_DOMAIN + canonical_json_bytes(document)
    )
    return verify_aer_config_layout(document)


def _current_layout_kwargs(
    layout: VerifiedAerConfigLayout,
) -> dict[str, object]:
    """Test adapter standing in for fresh owner/config-space observations."""

    return {
        "expected_device_identity_digest": layout.device_identity_digest,
        "expected_bdf": layout.bdf,
        "expected_host_boot_id": layout.host_boot_id,
        "expected_assignment_id": layout.assignment_id,
        "expected_lease_generation": layout.lease_generation,
        "expected_owner_epoch": layout.owner_epoch,
        "expected_pcie_capability_offset": layout.pcie_capability_offset,
        "expected_pcie_capability_header": layout.pcie_capability_header,
        "expected_pcie_capabilities_register": (
            layout.pcie_capabilities_register
        ),
        "expected_aer_capability_offset": layout.aer_capability_offset,
        "expected_aer_capability_header": layout.aer_capability_header,
        "expected_aer_predecessor_offset_or_none": (
            layout.aer_predecessor_offset_or_none
        ),
        "expected_aer_predecessor_header_or_none": (
            layout.aer_predecessor_header_or_none
        ),
    }


def _bind_executable_write(
    classification: VerifiedGuestConfigWriteClassification,
    policy: VerifiedAerPolicy,
    layout: VerifiedAerConfigLayout,
    *,
    operation_id: str = "aer-write-op-1",
    authority_revision: int = 17,
) -> VerifiedExecutableAerWritePlan:
    return require_pre_vfio_plan(
        classification,
        policy,
        layout,
        operation_id=operation_id,
        authority_revision=authority_revision,
        **_current_layout_kwargs(layout),
    )


def _consume_executable_write(
    plan: VerifiedExecutableAerWritePlan,
    *,
    operation_id: str = "aer-write-op-1",
    authority_revision: int = 17,
) -> tuple[PhysicalConfigWrite, ...]:
    return consume_executable_aer_write(
        plan,
        expected_operation_id=operation_id,
        expected_authority_revision=authority_revision,
        expected_aer_policy_digest=plan.aer_policy_digest,
        expected_layout_digest=plan.layout_digest,
    )


def _binding_document(environment_kind: str = "PHYSICAL") -> dict:
    return {
        "esxiBuild": "24280767",
        "environmentKind": environment_kind,
        "device": {
            "pciId": "1af4:1041",
            "requesterId": 0x101,
            "identityDigest": _hash("device"),
        },
        "owner": {
            "ownerPhase": "O4",
            "assignmentId": "assignment-a",
            "leaseGeneration": 7,
            "ownerEpoch": 11,
            "hostBootId": "boot-a",
        },
        "gate": "g101",
        "profileDigest": _hash("profile"),
        "backendDigest": _hash("backend"),
        "qmanBuildDigest": _hash("qman-build"),
        "implementationDigest": _hash("qman-aer-implementation"),
        "parityOracleDigest": _hash("vmware-parity-oracle"),
        "layoutDigest": _layout().layout_digest,
        "sourceHashes": [
            {"sourceId": "qemu-aer", "sha256": _hash("qemu-aer")},
            {"sourceId": "runner", "sha256": _hash("runner")},
        ],
    }


def _dimension_document(result: str = "VERIFIED") -> dict:
    return {dimension.value: result for dimension in AerDimension}


def _evidence_document(
    policy: VerifiedAerPolicy,
    *,
    classification: str = "MATCH",
    environment_kind: str = "PHYSICAL",
    dimension_result: str = "VERIFIED",
    cleanup: bool = True,
    reuse: bool = True,
) -> dict:
    document = {
        "subjectType": "QMAN_AER_CORRECTABLE_EVIDENCE",
        "schemaVersion": 1,
        "evidenceId": "aer-evidence-test",
        "aerPolicyDigest": policy.aer_policy_digest,
        "binding": _binding_document(environment_kind),
        "classification": classification,
        "complete": True,
        "integrityExact": True,
        "oracleExact": True,
        "identityExact": True,
        "sourceExact": True,
        "runtimeContainmentVerified": True,
        "oracleContainmentVerified": True,
        "containmentExact": True,
        "cleanupVerified": cleanup,
        "reuseGatePassed": reuse,
        "dimensions": _dimension_document(dimension_result),
        "caseResults": [
            {
                "caseId": case_id,
                "result": classification,
                "runResultDigest": _hash(f"{case_id}-run"),
                "artifactManifestDigest": _hash(f"{case_id}-manifest"),
                "oracleDigest": _hash(f"{case_id}-oracle"),
            }
            for case_id in AER_REQUIRED_CASE_IDS
        ],
        "evidenceDigest": None,
    }
    document["evidenceDigest"] = sha256_digest(
        AER_EVIDENCE_DIGEST_DOMAIN + canonical_json_bytes(document)
    )
    return document


def _qualification_document(
    policy: VerifiedAerPolicy,
    evidence: VerifiedAerEvidence,
    *,
    result: str = "QUALIFIED",
) -> dict:
    document = {
        "subjectType": "QMAN_AER_QUALIFICATION_BINDING",
        "schemaVersion": 1,
        "qualificationId": "aer-qualification-test",
        "authorityBoundary": AER_AUTHORITY_BOUNDARY,
        "aerPolicyDigest": policy.aer_policy_digest,
        "evidenceDigest": evidence.evidence_digest,
        "observationBindingDigest": evidence.binding.binding_digest,
        "caseIds": list(AER_REQUIRED_CASE_IDS),
        "e4EvidenceHashes": sorted(
            {
                evidence.evidence_digest,
                *(
                    digest
                    for item in evidence.case_results
                    for digest in (
                        item.run_result_digest,
                        item.artifact_manifest_digest,
                        item.oracle_digest,
                    )
                ),
            }
        ),
        "e4VerifierIdentityDigest": _hash("aer-e4-verifier-v1"),
        "e4ReplayReceiptDigest": _hash("aer-e4-replay-receipt"),
        "dimensionResults": {
            dimension.value: evidence.dimensions[dimension].value
            for dimension in AerDimension
        },
        "qualificationResult": result,
        "qualificationDigest": None,
    }
    document["qualificationDigest"] = sha256_digest(
        AER_QUALIFICATION_DIGEST_DOMAIN + canonical_json_bytes(document)
    )
    return document


class LegacyNoneAerE4Verifier:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def verify_aer_e4_closure(self, **kwargs) -> None:
        self.calls.append(kwargs)


class ReceiptResolver:
    def __init__(self, receipt: object) -> None:
        self.receipt = receipt
        self.calls: list[dict] = []

    def resolve_aer_e4_replay_receipt(self, **kwargs):
        self.calls.append(kwargs)
        return self.receipt


def _rehash_qualification(document: dict) -> None:
    document["qualificationDigest"] = None
    document["qualificationDigest"] = sha256_digest(
        AER_QUALIFICATION_DIGEST_DOMAIN + canonical_json_bytes(document)
    )


def _rehash_e4_receipt(document: dict) -> None:
    document["receiptDigest"] = None
    document["receiptDigest"] = sha256_digest(
        AER_E4_REPLAY_RECEIPT_DOMAIN + canonical_json_bytes(document)
    )


def _e4_replay_fixture(
    policy: VerifiedAerPolicy,
    evidence: VerifiedAerEvidence,
    *,
    verification_nonce: str = "aer-e4-nonce-1",
    authority_revision: int = 17,
    evaluated_at: datetime = NOW,
) -> tuple[dict, object, dict]:
    qualification = _qualification_document(policy, evidence)
    request = prepare_aer_e4_replay_request(
        policy,
        evidence,
        e4_evidence_hashes=tuple(qualification["e4EvidenceHashes"]),
        e4_verifier_identity_digest=qualification[
            "e4VerifierIdentityDigest"
        ],
        verification_nonce=verification_nonce,
        authority_revision=authority_revision,
        evaluated_at=evaluated_at,
    )
    request_document = load_canonical_json(request.canonical_bytes)
    receipt = {
        "subjectType": "QMAN_AER_E4_REPLAY_RECEIPT",
        "schemaVersion": 1,
        "replayId": "aer-e4-replay-1",
        "verificationNonce": request_document["verificationNonce"],
        "requestDigest": request.request_digest,
        "e4VerifierIdentityDigest": request.e4_verifier_identity_digest,
        "authorityRevision": request.authority_revision,
        "resolvedAt": request_document["evaluatedAt"],
        "validUntil": (
            evaluated_at + timedelta(seconds=30)
        ).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "aerPolicyDigest": request.aer_policy_digest,
        "policyBytesDigest": request.policy_bytes_digest,
        "evidenceDigest": request.evidence_digest,
        "evidenceBytesDigest": request.evidence_bytes_digest,
        "observationBindingDigest": request.observation_binding_digest,
        "layoutDigest": request.layout_digest,
        "device": copy.deepcopy(request_document["device"]),
        "owner": copy.deepcopy(request_document["owner"]),
        "caseResultsDigest": request.case_results_digest,
        "caseResults": copy.deepcopy(request_document["caseResults"]),
        "e4EvidenceHashes": list(request.e4_evidence_hashes),
        "dimensionResults": copy.deepcopy(
            request_document["dimensionResults"]
        ),
        "replayResult": "VERIFIED",
        "receiptDigest": None,
    }
    _rehash_e4_receipt(receipt)
    qualification["e4ReplayReceiptDigest"] = receipt["receiptDigest"]
    _rehash_qualification(qualification)
    return qualification, request, receipt


def _verified_chain(
    *,
    classification: str = "MATCH",
    environment_kind: str = "PHYSICAL",
    dimension_result: str = "VERIFIED",
    qualification_result: str = "QUALIFIED",
    cleanup: bool = True,
    reuse: bool = True,
):
    policy = verify_aer_policy(_policy_document())
    evidence = verify_aer_evidence(
        policy,
        _evidence_document(
            policy,
            classification=classification,
            environment_kind=environment_kind,
            dimension_result=dimension_result,
            cleanup=cleanup,
            reuse=reuse,
        ),
    )
    qualification = verify_aer_qualification(
        policy,
        evidence,
        _qualification_document(
            policy,
            evidence,
            result=qualification_result,
        ),
    )
    return policy, evidence, qualification


def _expectation(
    policy: VerifiedAerPolicy,
    evidence: VerifiedAerEvidence,
    qualification: VerifiedAerQualification,
) -> AerAdmissionExpectation:
    """Test-only stand-in for an independent current repository read."""

    binding = evidence.binding
    return AerAdmissionExpectation(
        aer_policy_digest=policy.aer_policy_digest,
        evidence_digest=evidence.evidence_digest,
        qualification_digest=qualification.qualification_digest,
        observation_binding_digest=binding.binding_digest,
        esxi_build=binding.esxi_build,
        environment_kind=binding.environment_kind,
        pci_id=binding.pci_id,
        requester_id=binding.requester_id,
        device_identity_digest=binding.device_identity_digest,
        owner_phase=binding.owner_phase,
        assignment_id=binding.assignment_id,
        lease_generation=binding.lease_generation,
        owner_epoch=binding.owner_epoch,
        host_boot_id=binding.host_boot_id,
        gate=binding.gate,
        profile_digest=binding.profile_digest,
        backend_digest=binding.backend_digest,
        qman_build_digest=binding.qman_build_digest,
        implementation_digest=binding.implementation_digest,
        parity_oracle_digest=binding.parity_oracle_digest,
        layout_digest=binding.layout_digest,
        current_authority_vector_digest=_hash("current-authority-vector"),
        source_hashes=binding.source_hashes,
    )


def _runtime_gate(
    expectation: AerAdmissionExpectation,
    *,
    cleanup: bool = True,
    reuse: bool = True,
    reset_clean: bool = True,
    quarantined: bool = False,
) -> AerRuntimeGate:
    return AerRuntimeGate(
        cleanup_verified=cleanup,
        reuse_gate_passed=reuse,
        reset_scope_clean=reset_clean,
        quarantined=quarantined,
        layout_digest=expectation.layout_digest,
        current_authority_vector_digest=(
            expectation.current_authority_vector_digest
        ),
        observed_at=NOW - timedelta(seconds=1),
        valid_until=NOW + timedelta(seconds=30),
    )


def _rehash_admission_current_receipt(document: dict) -> None:
    document["receiptDigest"] = None
    document["receiptDigest"] = sha256_digest(
        AER_ADMISSION_CURRENT_RECEIPT_DOMAIN
        + canonical_json_bytes(document)
    )


def _admission_current_receipt_fixture(
    policy: VerifiedAerPolicy,
    evidence: VerifiedAerEvidence,
    qualification: VerifiedAerQualification,
    expectation: AerAdmissionExpectation,
    *,
    verification_nonce: str = "admission-current-nonce-0001",
    authority_revision: int = 17,
    requested_at: datetime = NOW - timedelta(seconds=2),
    runtime_gate: AerRuntimeGate | None = None,
    resolved_at: datetime = NOW,
) -> tuple[AerAdmissionCurrentRequest, AerRuntimeGate, dict]:
    request = prepare_aer_admission_current_request(
        policy,
        evidence,
        qualification,
        expectation,
        verification_nonce=verification_nonce,
        authority_revision=authority_revision,
        requested_at=requested_at,
    )
    gate = (
        runtime_gate
        if runtime_gate is not None
        else _runtime_gate(expectation)
    )
    request_document = load_canonical_json(request.canonical_bytes)
    receipt = {
        "subjectType": "QMAN_AER_ADMISSION_CURRENT_RECEIPT",
        "schemaVersion": 1,
        "receiptId": "admission-current-receipt-1",
        "verificationNonce": request.verification_nonce,
        "requestDigest": request.request_digest,
        "authorityRevision": request.authority_revision,
        "requestedAt": request_document["requestedAt"],
        "resolvedAt": resolved_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "aerPolicyDigest": request_document["aerPolicyDigest"],
        "policyBytesDigest": request_document["policyBytesDigest"],
        "evidenceDigest": request_document["evidenceDigest"],
        "evidenceBytesDigest": request_document["evidenceBytesDigest"],
        "qualificationDigest": request_document["qualificationDigest"],
        "qualificationBytesDigest": request_document[
            "qualificationBytesDigest"
        ],
        "observationBindingDigest": request_document[
            "observationBindingDigest"
        ],
        "layoutDigest": request_document["layoutDigest"],
        "device": copy.deepcopy(request_document["device"]),
        "owner": copy.deepcopy(request_document["owner"]),
        "currentAuthorityVectorDigest": request_document[
            "currentAuthorityVectorDigest"
        ],
        "runtimeGate": {
            "cleanupVerified": gate.cleanup_verified,
            "reuseGatePassed": gate.reuse_gate_passed,
            "resetScopeClean": gate.reset_scope_clean,
            "quarantined": gate.quarantined,
            "layoutDigest": gate.layout_digest,
            "currentAuthorityVectorDigest": (
                gate.current_authority_vector_digest
            ),
            "observedAt": gate.observed_at.strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ"
            ),
            "validUntil": gate.valid_until.strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ"
            ),
        },
        "sourceHashes": copy.deepcopy(request_document["sourceHashes"]),
        "caseResultsDigest": request_document["caseResultsDigest"],
        "caseResults": copy.deepcopy(request_document["caseResults"]),
        "e4EvidenceHashes": list(request_document["e4EvidenceHashes"]),
        "cas": {
            "nonce": request.verification_nonce,
            "expectedAuthorityRevision": request.authority_revision,
            "committedAuthorityRevision": request.authority_revision + 1,
            "consumedAt": resolved_at.strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ"
            ),
        },
        "receiptDigest": None,
    }
    _rehash_admission_current_receipt(receipt)
    return request, gate, receipt


class M24CorrectableDepositionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = verify_aer_policy(_policy_document())

    def test_all_eight_correctable_bits_deposit_and_clear_independently(self) -> None:
        self.assertEqual(CORRECTABLE_ERROR_ALLOW_MASK, sum(CORRECTABLE_BITS))
        for bit in CORRECTABLE_BITS:
            with self.subTest(bit=hex(bit)):
                model = AerReferenceModel.initial(
                    policy=self.policy,
                    route=CorrectableRouteControl(
                        endpoint_reporting_enabled=False,
                        correctable_error_mask=0,
                        root_correctable_notification_enabled=False,
                    ),
                    endpoint_requester_id=0x101,
                ).inject_correctable(bit, requester_id=0x101)
                self.assertEqual(bit, model.physical.endpoint_correctable_status)
                self.assertTrue(model.physical.endpoint_correctable_detected)
                self.assertEqual(0, model.physical.root_correctable_status)

                ces_cleared = model.endpoint_status_w1c(bit)
                self.assertEqual(0, ces_cleared.physical.endpoint_correctable_status)
                self.assertTrue(ces_cleared.physical.endpoint_correctable_detected)
                ced_cleared = ces_cleared.endpoint_device_status_w1c()
                self.assertFalse(ced_cleared.physical.endpoint_correctable_detected)

    def test_any_uncorrectable_input_fails_closed(self) -> None:
        model = AerReferenceModel.initial(
            policy=self.policy,
            route=CorrectableRouteControl(True, 0, True),
            endpoint_requester_id=0x101,
        )
        with self.assertRaises(DirectPathVerificationError) as raised:
            model.inject_correctable(
                0x1,
                requester_id=0x101,
                uncorrectable_status=0x1,
            )
        self.assertEqual("AER_UNCORRECTABLE_FORBIDDEN", raised.exception.code)
        with self.assertRaises(DirectPathVerificationError):
            PhysicalCorrectableState(endpoint_uncorrectable_status=1)


class M25RouteTruthTableTests(unittest.TestCase):
    def test_e_and_m_route_while_r_only_controls_notification(self) -> None:
        policy = verify_aer_policy(_policy_document())
        for endpoint_enabled in (False, True):
            for masked in (False, True):
                for root_notification in (False, True):
                    with self.subTest(
                        endpoint_enabled=endpoint_enabled,
                        masked=masked,
                        root_notification=root_notification,
                    ):
                        model = AerReferenceModel.initial(
                            policy=policy,
                            route=CorrectableRouteControl(
                                endpoint_reporting_enabled=endpoint_enabled,
                                correctable_error_mask=0x1 if masked else 0,
                                root_correctable_notification_enabled=(
                                    root_notification
                                ),
                            ),
                            endpoint_requester_id=0x101,
                        ).inject_correctable(0x1, requester_id=0x101)
                        routed = endpoint_enabled and not masked
                        self.assertEqual(
                            bool(
                                model.physical.root_correctable_status
                                & ROOT_CORRECTABLE_RECEIVED
                            ),
                            routed,
                        )
                        self.assertEqual(
                            model.notification.routed_message_count,
                            int(routed),
                        )
                        self.assertEqual(
                            model.notification.notification_eligible_count,
                            int(routed and root_notification),
                        )
                        self.assertEqual(
                            model.physical.endpoint_correctable_status,
                            0x1,
                        )
                        self.assertTrue(
                            model.physical.endpoint_correctable_detected
                        )


class M26RetainedSequenceTests(unittest.TestCase):
    def test_first_multiple_or_independent_w1c_and_rearm(self) -> None:
        policy = verify_aer_policy(_policy_document())
        model = AerReferenceModel.initial(
            policy=policy,
            route=CorrectableRouteControl(True, 0, True),
            endpoint_requester_id=0x101,
        )
        first = model.inject_correctable(0x1, requester_id=0x101)
        self.assertEqual(ROOT_CORRECTABLE_RECEIVED, first.physical.root_correctable_status)
        self.assertEqual(0x101, first.physical.root_source_semantic)

        multiple = first.inject_correctable(0x40, requester_id=0x101)
        self.assertEqual(0x41, multiple.physical.endpoint_correctable_status)
        self.assertEqual(
            ROOT_CORRECTABLE_RECEIVED | ROOT_MULTIPLE_CORRECTABLE_RECEIVED,
            multiple.physical.root_correctable_status,
        )
        self.assertEqual(0x101, multiple.physical.root_correctable_source_raw)

        endpoint_clear = multiple.endpoint_status_w1c(0x41)
        self.assertEqual(0, endpoint_clear.physical.endpoint_correctable_status)
        self.assertTrue(endpoint_clear.physical.endpoint_correctable_detected)
        self.assertEqual(3, endpoint_clear.physical.root_correctable_status)
        endpoint_clear = endpoint_clear.endpoint_device_status_w1c()
        self.assertFalse(endpoint_clear.physical.endpoint_correctable_detected)

        root_clear = endpoint_clear.root_status_w1c(3)
        self.assertEqual(0, root_clear.physical.root_correctable_status)
        self.assertEqual(0x101, root_clear.physical.root_correctable_source_raw)
        self.assertIsNone(root_clear.physical.root_source_semantic)
        root_layout = _layout(role=AerFunctionRole.ROOT_PORT)
        projected_source = root_clear.guest_root_source_read(
            layout=root_layout,
            snapshot_id="m26-root-source-after-clear",
            authority_revision=17,
            **_current_layout_kwargs(root_layout),
        )
        self.assertEqual(0x101, projected_source.raw_value)
        self.assertFalse(projected_source.semantic_valid)
        self.assertIsNone(projected_source.semantic_requester_id)

        rearmed = root_clear.inject_correctable(0x1, requester_id=0x101)
        self.assertEqual(1, rearmed.physical.root_correctable_status)
        self.assertEqual(0x101, rearmed.physical.root_source_semantic)
        with self.assertRaises(DirectPathVerificationError) as raised:
            rearmed.inject_correctable(0x40, requester_id=0x102)
        self.assertEqual("AER_REQUESTER_ID_MISMATCH", raised.exception.code)

    def test_irq_service_health_and_recovery_are_not_inferred(self) -> None:
        policy = verify_aer_policy(_policy_document())
        model = AerReferenceModel.initial(
            policy=policy,
            route=CorrectableRouteControl(True, 0, True),
            endpoint_requester_id=0x101,
        ).inject_correctable(1, requester_id=0x101)
        self.assertEqual(1, model.notification.notification_eligible_count)
        self.assertEqual(Observation.UNKNOWN, model.notification.irq)
        self.assertEqual(Observation.UNKNOWN, model.notification.service)
        self.assertEqual(Observation.UNKNOWN, model.notification.health)
        self.assertEqual(
            Observation.UNKNOWN,
            model.notification.physical_recovery,
        )
        observed = model.record_observations(irq=Observation.OBSERVED)
        conflict = observed.record_observations(
            irq=Observation.NOT_OBSERVED
        )
        self.assertEqual(Observation.CONFLICT, conflict.notification.irq)
        retained = conflict.record_observations(irq=Observation.UNKNOWN)
        self.assertEqual(Observation.CONFLICT, retained.notification.irq)


class P12ShadowSourceAfterGuestW1cTests(unittest.TestCase):
    def test_shadow_source_semantics_follow_guest_visible_cor_rcv_after_w1c(
        self,
    ) -> None:
        policy = verify_aer_policy(
            _policy_document(
                header="HIDDEN",
                body="HIDDEN",
                hidden_read="SHADOW",
                physical_writes=False,
            )
        )
        layout = _layout(role=AerFunctionRole.ROOT_PORT)
        injected = AerReferenceModel.initial(
            policy=policy,
            route=CorrectableRouteControl(True, 0, True),
            endpoint_requester_id=0x101,
        ).inject_correctable(1, requester_id=0x101)

        cleared, plan = injected.apply_guest_config_write(
            layout=layout,
            write_offset=layout.aer_capability_offset + 0x30,
            width=4,
            value=ROOT_CORRECTABLE_RECEIVED,
            operation_id="shadow-root-status-clear",
            authority_revision=21,
            **_current_layout_kwargs(layout),
        )

        self.assertEqual(0, plan.physical_write_count)
        self.assertEqual(
            ROOT_CORRECTABLE_RECEIVED,
            cleared.physical.root_correctable_status,
        )
        self.assertEqual(
            0,
            cleared.guest.value(AerField.ROOT_ERROR_STATUS),
        )
        projected = cleared.guest_root_source_read(
            layout=layout,
            snapshot_id="shadow-source-after-guest-w1c",
            authority_revision=22,
            **_current_layout_kwargs(layout),
        )
        self.assertEqual(0x101, projected.raw_value)
        self.assertFalse(projected.semantic_valid)
        self.assertIsNone(projected.semantic_requester_id)


class P12ShadowSourceAfterPhysicalClearTests(unittest.TestCase):
    def test_physical_clear_does_not_override_shadow_cor_rcv_semantics(
        self,
    ) -> None:
        policy = verify_aer_policy(
            _policy_document(
                header="HIDDEN",
                body="HIDDEN",
                hidden_read="SHADOW",
                physical_writes=False,
            )
        )
        layout = _layout(role=AerFunctionRole.ROOT_PORT)
        injected = AerReferenceModel.initial(
            policy=policy,
            route=CorrectableRouteControl(True, 0, True),
            endpoint_requester_id=0x101,
        ).inject_correctable(1, requester_id=0x101)
        physical_cleared = injected.root_status_w1c(
            ROOT_CORRECTABLE_RECEIVED
        )

        self.assertEqual(
            0,
            physical_cleared.physical.root_correctable_status,
        )
        self.assertEqual(
            ROOT_CORRECTABLE_RECEIVED,
            physical_cleared.guest.value(AerField.ROOT_ERROR_STATUS),
        )
        projected = physical_cleared.guest_root_source_read(
            layout=layout,
            snapshot_id="shadow-source-after-physical-clear",
            authority_revision=23,
            **_current_layout_kwargs(layout),
        )
        self.assertEqual(0x101, projected.raw_value)
        self.assertTrue(projected.semantic_valid)
        self.assertEqual(0x101, projected.semantic_requester_id)


class P12CallerSemanticAssertionTests(unittest.TestCase):
    def test_source_semantic_validity_cannot_be_caller_asserted(self) -> None:
        policy = verify_aer_policy(_policy_document())
        layout = _layout(role=AerFunctionRole.ROOT_PORT)

        with self.assertRaises(TypeError):
            project_guest_config_read(
                policy,
                layout,
                read_offset=layout.aer_capability_offset + 0x34,
                width=2,
                physical_field_values={
                    AerField.ROOT_ERROR_STATUS: 0,
                    AerField.ERROR_SOURCE_ID: 0x101,
                },
                shadow_field_values={},
                root_source_semantic_valid=True,
                **_current_layout_kwargs(layout),
            )
        with self.assertRaises(TypeError):
            project_guest_root_source_read(
                policy,
                physical_value=0x101,
                root_correctable_received=True,
            )
        with self.assertRaises(TypeError):
            VerifiedGuestProjectedAerSnapshot._construct(
                source_semantic_valid=True,
            )

        for root_field in (
            AerField.ROOT_ERROR_STATUS,
            AerField.ERROR_SOURCE_ID,
        ):
            with self.subTest(raw_field=root_field):
                with self.assertRaises(
                    DirectPathVerificationError
                ) as raw_bypass:
                    project_guest_read(
                        policy,
                        root_field,
                        physical_value=ROOT_CORRECTABLE_RECEIVED,
                    )
                self.assertEqual(
                    "AER_ROOT_SNAPSHOT_REQUIRED",
                    raw_bypass.exception.code,
                )
        model = AerReferenceModel.initial(
            policy=policy,
            route=CorrectableRouteControl(True, 0, True),
            endpoint_requester_id=0x101,
        ).inject_correctable(1, requester_id=0x101)
        for root_field in (
            AerField.ROOT_ERROR_STATUS,
            AerField.ERROR_SOURCE_ID,
        ):
            with self.subTest(model_field=root_field):
                with self.assertRaises(
                    DirectPathVerificationError
                ) as model_bypass:
                    model.guest_read(
                        root_field,
                        function_role=AerFunctionRole.ROOT_PORT,
                    )
                self.assertEqual(
                    "AER_ROOT_SNAPSHOT_REQUIRED",
                    model_bypass.exception.code,
                )


class P12PartialSourceMaskTests(unittest.TestCase):
    def test_partial_or_zero_source_mask_never_yields_requester_identity(
        self,
    ) -> None:
        layout = _layout(role=AerFunctionRole.ROOT_PORT)
        for source_mask, expected_raw in ((0, 0), (0xFF, 0x01)):
            with self.subTest(source_mask=hex(source_mask)):
                document = _policy_document()
                document["fields"]["ERROR_SOURCE_ID"][
                    "guestReadAllowMask"
                ] = source_mask
                document["aerPolicyDigest"] = None
                document["aerPolicyDigest"] = sha256_digest(
                    AER_POLICY_DIGEST_DOMAIN
                    + canonical_json_bytes(document)
                )
                policy = verify_aer_policy(document)
                snapshot_id = f"partial-source-mask-{source_mask:x}"
                snapshot = project_guest_aer_snapshot(
                    policy,
                    layout,
                    snapshot_id=snapshot_id,
                    authority_revision=24,
                    physical_field_values={
                        AerField.ROOT_ERROR_STATUS: (
                            ROOT_CORRECTABLE_RECEIVED
                        ),
                        AerField.ERROR_SOURCE_ID: 0x101,
                    },
                    shadow_field_values={},
                    **_current_layout_kwargs(layout),
                )
                projected = project_guest_root_source_read(
                    snapshot,
                    expected_snapshot_id=snapshot_id,
                    expected_authority_revision=24,
                )

                self.assertEqual(expected_raw, projected.raw_value)
                self.assertFalse(projected.semantic_valid)
                self.assertIsNone(projected.semantic_requester_id)


class P12AtomicRootSnapshotTests(unittest.TestCase):
    def test_root_status_and_source_require_one_atomic_snapshot(self) -> None:
        policy = verify_aer_policy(_policy_document())
        layout = _layout(role=AerFunctionRole.ROOT_PORT)
        with self.assertRaises(DirectPathVerificationError) as missing:
            project_guest_config_read(
                policy,
                layout,
                read_offset=layout.aer_capability_offset + 0x34,
                width=2,
                physical_field_values={
                    AerField.ROOT_ERROR_STATUS: (
                        ROOT_CORRECTABLE_RECEIVED
                    ),
                    AerField.ERROR_SOURCE_ID: 0x101,
                },
                shadow_field_values={},
                **_current_layout_kwargs(layout),
            )
        self.assertEqual("AER_ROOT_SNAPSHOT_REQUIRED", missing.exception.code)

        with self.assertRaises(DirectPathVerificationError) as incomplete:
            project_guest_aer_snapshot(
                policy,
                layout,
                snapshot_id="incomplete-root-snapshot",
                authority_revision=25,
                physical_field_values={
                    AerField.ROOT_ERROR_STATUS: (
                        ROOT_CORRECTABLE_RECEIVED
                    ),
                },
                shadow_field_values={},
                **_current_layout_kwargs(layout),
            )
        self.assertEqual(
            "AER_ROOT_SNAPSHOT_INCOMPLETE",
            incomplete.exception.code,
        )

        snapshot = project_guest_aer_snapshot(
            policy,
            layout,
            snapshot_id="one-atomic-root-snapshot",
            authority_revision=25,
            physical_field_values={
                AerField.ROOT_ERROR_STATUS: ROOT_CORRECTABLE_RECEIVED,
                AerField.ERROR_SOURCE_ID: 0x101,
            },
            shadow_field_values={
                AerField.ROOT_ERROR_STATUS: 0,
                AerField.ERROR_SOURCE_ID: 0xBEEF,
            },
            **_current_layout_kwargs(layout),
        )
        for expected_id, expected_revision in (
            ("other-root-snapshot", 25),
            ("one-atomic-root-snapshot", 26),
        ):
            with self.subTest(
                expected_id=expected_id,
                expected_revision=expected_revision,
            ):
                with self.assertRaises(
                    DirectPathVerificationError
                ) as stale_identity:
                    project_guest_root_source_read(
                        snapshot,
                        expected_snapshot_id=expected_id,
                        expected_authority_revision=expected_revision,
                    )
                self.assertEqual(
                    "AER_ROOT_SNAPSHOT_BINDING_MISMATCH",
                    stale_identity.exception.code,
                )
        conflicting_values = {
            AerField.ROOT_ERROR_STATUS: 0,
            AerField.ERROR_SOURCE_ID: 0xBEEF,
        }
        root_status = project_guest_config_read(
            policy,
            layout,
            read_offset=layout.aer_capability_offset + 0x30,
            width=4,
            physical_field_values=conflicting_values,
            shadow_field_values={},
            root_snapshot=snapshot,
            expected_root_snapshot_id="one-atomic-root-snapshot",
            expected_root_snapshot_authority_revision=25,
            **_current_layout_kwargs(layout),
        )
        source = project_guest_config_read(
            policy,
            layout,
            read_offset=layout.aer_capability_offset + 0x34,
            width=2,
            physical_field_values=conflicting_values,
            shadow_field_values={},
            root_snapshot=snapshot,
            expected_root_snapshot_id="one-atomic-root-snapshot",
            expected_root_snapshot_authority_revision=25,
            **_current_layout_kwargs(layout),
        )
        self.assertEqual(ROOT_CORRECTABLE_RECEIVED, root_status.value)
        self.assertEqual(0x101, source.value)
        self.assertEqual(
            "one-atomic-root-snapshot",
            root_status.root_snapshot_id,
        )
        self.assertEqual(25, source.root_snapshot_authority_revision)
        self.assertTrue(source.root_source_semantic_valid)
        self.assertEqual(
            0x101,
            source.root_source_semantic_requester_id,
        )

        new_owner_document = dict(layout.document)
        new_owner_document["ownerEpoch"] = layout.owner_epoch + 1
        new_owner_document["layoutDigest"] = None
        new_owner_document["layoutDigest"] = sha256_digest(
            AER_CONFIG_LAYOUT_DIGEST_DOMAIN
            + canonical_json_bytes(new_owner_document)
        )
        new_owner_layout = verify_aer_config_layout(new_owner_document)
        with self.assertRaises(DirectPathVerificationError) as stale:
            project_guest_config_read(
                policy,
                new_owner_layout,
                read_offset=new_owner_layout.aer_capability_offset + 0x30,
                width=4,
                physical_field_values={},
                shadow_field_values={},
                root_snapshot=snapshot,
                expected_root_snapshot_id="one-atomic-root-snapshot",
                expected_root_snapshot_authority_revision=25,
                **_current_layout_kwargs(new_owner_layout),
            )
        self.assertEqual(
            "AER_ROOT_SNAPSHOT_BINDING_MISMATCH",
            stale.exception.code,
        )


class M27LifecycleAndFenceTests(unittest.TestCase):
    def test_cleanup_and_reuse_are_separate_fail_closed_transitions(self) -> None:
        policy = verify_aer_policy(_policy_document())
        dirty = AerReferenceModel.initial(
            policy=policy,
            route=CorrectableRouteControl(True, 0, True),
            endpoint_requester_id=0x101,
        ).inject_correctable(1, requester_id=0x101)
        quarantined = dirty.assess_cleanup()
        self.assertEqual(LifecyclePhase.QUARANTINED, quarantined.lifecycle.phase)

        cleared = (
            dirty.endpoint_status_w1c(1)
            .endpoint_device_status_w1c()
            .root_status_w1c(3)
            .assess_cleanup()
        )
        self.assertEqual(LifecyclePhase.CLEANUP_VERIFIED, cleared.lifecycle.phase)
        reusable = cleared.assess_reuse_gate(passed=True)
        self.assertEqual(LifecyclePhase.REUSABLE, reusable.lifecycle.phase)
        failed_reuse = cleared.assess_reuse_gate(passed=False)
        self.assertEqual(
            LifecyclePhase.QUARANTINED,
            failed_reuse.lifecycle.phase,
        )

    def test_shadow_state_requires_host_cleanup_before_reuse(self) -> None:
        policy = verify_aer_policy(
            _policy_document(
                header="HIDDEN",
                body="HIDDEN",
                hidden_read="SHADOW",
                physical_writes=False,
            )
        )
        layout = _layout()
        dirty = AerReferenceModel.initial(
            policy=policy,
            route=CorrectableRouteControl(True, 0, True),
            endpoint_requester_id=0x101,
        ).inject_correctable(1, requester_id=0x101)
        self.assertEqual(
            1,
            dirty.guest_read(AerField.CORRECTABLE_ERROR_STATUS),
        )
        guest_cleared, plan = dirty.apply_guest_config_write(
            layout=layout,
            write_offset=layout.aer_capability_offset + 0x10,
            width=1,
            value=1,
            operation_id="shadow-clear-op",
            authority_revision=17,
            **_current_layout_kwargs(layout),
        )
        self.assertEqual(0, plan.physical_write_count)
        self.assertTrue(plan.consumed)
        self.assertFalse(plan.classification.physical_write_required)
        self.assertEqual(
            0,
            guest_cleared.guest_read(AerField.CORRECTABLE_ERROR_STATUS),
        )
        self.assertEqual(
            1,
            guest_cleared.physical.endpoint_correctable_status,
        )

        physical_cleared = (
            dirty.endpoint_status_w1c(1)
            .endpoint_device_status_w1c()
            .root_status_w1c(3)
        )
        self.assertFalse(physical_cleared.guest.error_state_clean)
        self.assertEqual(
            LifecyclePhase.QUARANTINED,
            physical_cleared.assess_cleanup().lifecycle.phase,
        )
        remediated = (
            physical_cleared.host_cleanup_guest_shadow().assess_cleanup()
        )
        self.assertEqual(
            LifecyclePhase.CLEANUP_VERIFIED,
            remediated.lifecycle.phase,
        )

    def test_stale_assignment_lease_epoch_and_boot_are_denied(self) -> None:
        policy, evidence, qualification = _verified_chain()
        expectation = _expectation(policy, evidence, qualification)
        gate = _runtime_gate(expectation)
        attempts = (
            (
                replace(expectation, assignment_id="assignment-b"),
                AerAdmissionDenyReason.ASSIGNMENT_MISMATCH,
            ),
            (
                replace(expectation, lease_generation=8),
                AerAdmissionDenyReason.STALE_LEASE_GENERATION_REJECTED,
            ),
            (
                replace(expectation, owner_epoch=12),
                AerAdmissionDenyReason.STALE_OWNER_EPOCH_REJECTED,
            ),
            (
                replace(expectation, host_boot_id="boot-b"),
                AerAdmissionDenyReason.STALE_HOST_BOOT_REJECTED,
            ),
        )
        for changed, expected in attempts:
            with self.subTest(expected=expected):
                decision = evaluate_aer_admission(
                    policy=policy,
                    evidence=evidence,
                    qualification=qualification,
                    expectation=changed,
                    runtime_gate=gate,
                    checked_at=NOW,
                )
                self.assertFalse(decision.component_eligible)
                self.assertIn(expected, decision.deny_reasons)


class M28GuestConfigIsolationTests(unittest.TestCase):
    def test_w1c_byte_lanes_dynamic_offsets_and_role_are_exact(self) -> None:
        policy = verify_aer_policy(_policy_document())
        endpoint_layout = _layout()
        plan = plan_guest_config_write(
            policy,
            endpoint_layout,
            write_offset=0x190,
            width=1,
            value=0xFF,
        )
        executable = _bind_executable_write(plan, policy, endpoint_layout)
        self.assertEqual(plan, executable.classification)
        self.assertEqual(FILTER_BEFORE_VFIO, plan.filter_stage)
        self.assertFalse(hasattr(plan, "physical_writes"))
        self.assertTrue(plan.physical_write_required)
        physical_writes = _consume_executable_write(executable)
        self.assertEqual(0xC1, physical_writes[0].value)
        self.assertEqual(0xC1, plan.forwarded_request_mask)
        self.assertEqual(0x3E, plan.discarded_request_mask)
        self.assertIn(WriteDenyReason.W1C_BITS_FILTERED, plan.deny_reasons)

        unaligned_layout = _layout(aer_offset=0x240, pcie_offset=0x90)
        unaligned = plan_guest_config_write(
            policy,
            unaligned_layout,
            write_offset=0x251,
            width=2,
            value=0xFFFF,
        )
        unaligned_executable = _bind_executable_write(
            unaligned,
            policy,
            unaligned_layout,
            operation_id="unaligned-op",
        )
        unaligned_writes = _consume_executable_write(
            unaligned_executable,
            operation_id="unaligned-op",
        )
        self.assertEqual(0x0000F100, unaligned_writes[0].value)
        self.assertEqual(0x00F1, unaligned.forwarded_request_mask)
        self.assertEqual(0xFF0E, unaligned.discarded_request_mask)
        self.assertEqual(0x250, unaligned_writes[0].offset)

        endpoint_root_offset = plan_guest_config_write(
            policy,
            endpoint_layout,
            write_offset=0x1B0,
            width=1,
            value=3,
        )
        self.assertFalse(endpoint_root_offset.physical_write_required)
        root_layout = _layout(role=AerFunctionRole.ROOT_PORT)
        root_plan = plan_guest_config_write(
            policy,
            root_layout,
            write_offset=0x1B0,
            width=1,
            value=0xFF,
        )
        root_executable = _bind_executable_write(
            root_plan,
            policy,
            root_layout,
            operation_id="root-op",
        )
        root_writes = _consume_executable_write(
            root_executable,
            operation_id="root-op",
        )
        self.assertEqual(3, root_writes[0].value)

    def test_read_projection_masks_every_lane_and_never_raw_falls_back(self) -> None:
        policy = verify_aer_policy(_policy_document())
        endpoint_layout = _layout()
        root_layout = _layout(role=AerFunctionRole.ROOT_PORT)
        raw = {field: 0xFFFFFFFF for field in AerField}

        endpoint_status = project_guest_config_read(
            policy,
            endpoint_layout,
            read_offset=endpoint_layout.pcie_capability_offset + 0x0A,
            width=2,
            physical_field_values=raw,
            shadow_field_values={},
            **_current_layout_kwargs(endpoint_layout),
        )
        self.assertEqual(1, endpoint_status.value)

        root_snapshot = project_guest_aer_snapshot(
            policy,
            root_layout,
            snapshot_id="m28-root-read",
            authority_revision=17,
            physical_field_values=raw,
            shadow_field_values={},
            **_current_layout_kwargs(root_layout),
        )
        root_status = project_guest_config_read(
            policy,
            root_layout,
            read_offset=root_layout.aer_capability_offset + 0x30,
            width=4,
            physical_field_values=raw,
            shadow_field_values={},
            root_snapshot=root_snapshot,
            expected_root_snapshot_id="m28-root-read",
            expected_root_snapshot_authority_revision=17,
            **_current_layout_kwargs(root_layout),
        )
        self.assertEqual(3, root_status.value)
        source = project_guest_config_read(
            policy,
            root_layout,
            read_offset=root_layout.aer_capability_offset + 0x34,
            width=4,
            physical_field_values=raw,
            shadow_field_values={},
            root_snapshot=root_snapshot,
            expected_root_snapshot_id="m28-root-read",
            expected_root_snapshot_authority_revision=17,
            **_current_layout_kwargs(root_layout),
        )
        self.assertEqual(0xFFFF, source.value)
        self.assertTrue(source.root_source_semantic_valid)
        self.assertEqual(0xFFFF, source.root_source_semantic_requester_id)

        for offset, expected_disposition in (
            (
                endpoint_layout.aer_capability_offset + 0x04,
                ReadLaneDisposition.UNCORRECTABLE_ZEROED,
            ),
            (0x300, ReadLaneDisposition.UNKNOWN_ZEROED),
        ):
            with self.subTest(offset=hex(offset)):
                projected = project_guest_config_read(
                    policy,
                    endpoint_layout,
                    read_offset=offset,
                    width=4,
                    physical_field_values=raw,
                    shadow_field_values={},
                    **_current_layout_kwargs(endpoint_layout),
                )
                self.assertEqual(0, projected.value)
                self.assertTrue(
                    all(
                        disposition is expected_disposition
                        for disposition in projected.lane_dispositions
                    )
                )

        missing = project_guest_config_read(
            policy,
            endpoint_layout,
            read_offset=endpoint_layout.aer_capability_offset + 0x10,
            width=1,
            physical_field_values={},
            shadow_field_values={},
            **_current_layout_kwargs(endpoint_layout),
        )
        self.assertEqual(0, missing.value)
        self.assertEqual(
            (ReadLaneDisposition.MISSING_FIELD_ZEROED,),
            missing.lane_dispositions,
        )

        hidden = verify_aer_policy(
            _policy_document(
                header="HIDDEN",
                body="HIDDEN",
                hidden_read="ZERO",
                physical_writes=False,
            )
        )
        predecessor = project_guest_config_read(
            hidden,
            endpoint_layout,
            read_offset=0x140,
            width=4,
            physical_field_values=raw,
            shadow_field_values={},
            **_current_layout_kwargs(endpoint_layout),
        )
        self.assertEqual(0x00010010, predecessor.value)
        hidden_header = project_guest_config_read(
            hidden,
            endpoint_layout,
            read_offset=endpoint_layout.aer_capability_offset,
            width=4,
            physical_field_values=raw,
            shadow_field_values={},
            **_current_layout_kwargs(endpoint_layout),
        )
        self.assertEqual(0, hidden_header.value)
        self.assertTrue(
            all(
                item is ReadLaneDisposition.HIDDEN_ZEROED
                for item in hidden_header.lane_dispositions
            )
        )
        hidden_body = project_guest_config_read(
            hidden,
            endpoint_layout,
            read_offset=endpoint_layout.aer_capability_offset + 0x10,
            width=4,
            physical_field_values=raw,
            shadow_field_values={},
            **_current_layout_kwargs(endpoint_layout),
        )
        self.assertEqual(0, hidden_body.value)

    def test_unbound_and_stale_classifications_cannot_execute(self) -> None:
        policy = verify_aer_policy(_policy_document())
        layout = _layout()
        classification = plan_guest_config_write(
            policy,
            layout,
            write_offset=layout.aer_capability_offset + 0x10,
            width=1,
            value=1,
        )
        self.assertIsInstance(
            classification,
            VerifiedGuestConfigWriteClassification,
        )
        self.assertFalse(hasattr(classification, "physical_writes"))
        with self.assertRaises(DirectPathVerificationError) as unbound:
            consume_executable_aer_write(
                classification,
                expected_operation_id="unbound-op",
                expected_authority_revision=17,
                expected_aer_policy_digest=policy.aer_policy_digest,
                expected_layout_digest=layout.layout_digest,
            )
        self.assertEqual(
            "AER_EXECUTABLE_WRITE_PLAN_INVALID",
            unbound.exception.code,
        )

        forged_values = {
            item.name: getattr(classification, item.name)
            for item in fields(classification)
        }
        forged_values["request_value"] = 0xFF
        forged = VerifiedGuestConfigWritePlan._construct(**forged_values)
        with self.assertRaises(DirectPathVerificationError) as raised:
            require_pre_vfio_plan(
                forged,
                policy,
                layout,
                operation_id="forged-op",
                authority_revision=17,
                **_current_layout_kwargs(layout),
            )
        self.assertEqual("AER_WRITE_PLAN_INVALID", raised.exception.code)

        stale_layout = _layout(aer_offset=0x174)
        stale_plan = plan_guest_config_write(
            policy,
            stale_layout,
            write_offset=0x184,
            width=1,
            value=1,
        )
        self.assertFalse(hasattr(stale_plan, "physical_writes"))
        with self.assertRaises(DirectPathVerificationError):
            require_pre_vfio_plan(
                stale_plan,
                policy,
                stale_layout,
                operation_id="stale-op",
                authority_revision=17,
                expected_device_identity_digest=_hash("device"),
                expected_bdf="0000:01:00.1",
                expected_host_boot_id="boot-a",
                expected_assignment_id="assignment-a",
                expected_lease_generation=7,
                expected_owner_epoch=11,
                expected_pcie_capability_offset=0x70,
                expected_pcie_capability_header=0x0010,
                expected_pcie_capabilities_register=0x0000,
                expected_aer_capability_offset=0x180,
                expected_aer_capability_header=0x00010001,
                expected_aer_predecessor_offset_or_none=0x140,
                expected_aer_predecessor_header_or_none=0x18010010,
            )
        current_layout = _layout()
        with self.assertRaises(DirectPathVerificationError) as stale_read:
            project_guest_config_read(
                policy,
                stale_layout,
                # Stale +0x10 labels current +0x04 UES as CES.
                read_offset=0x184,
                width=4,
                physical_field_values={
                    AerField.CORRECTABLE_ERROR_STATUS: 0xFFFFFFFF
                },
                shadow_field_values={},
                **_current_layout_kwargs(current_layout),
            )
        self.assertEqual("AER_CONFIG_LAYOUT_STALE", stale_read.exception.code)

        current = _layout()
        mutations = {
            "expected_device_identity_digest": _hash("other-device"),
            "expected_bdf": "0000:02:00.0",
            "expected_host_boot_id": "boot-b",
            "expected_assignment_id": "assignment-b",
            "expected_lease_generation": 8,
            "expected_owner_epoch": 12,
            "expected_pcie_capability_offset": 0x74,
            "expected_pcie_capability_header": 0x4010,
            "expected_pcie_capabilities_register": 0x0040,
            "expected_aer_capability_offset": 0x184,
            "expected_aer_capability_header": 0x20010001,
            "expected_aer_predecessor_offset_or_none": 0x144,
            "expected_aer_predecessor_header_or_none": 0x18410010,
        }
        for name, changed_value in mutations.items():
            with self.subTest(current_binding=name):
                current_inputs = _current_layout_kwargs(current)
                current_inputs[name] = changed_value
                with self.assertRaises(DirectPathVerificationError) as stale:
                    require_current_aer_layout(current, **current_inputs)
                self.assertEqual(
                    "AER_CONFIG_LAYOUT_STALE",
                    stale.exception.code,
                )

    def test_executable_plan_binding_and_single_consume_are_exact(self) -> None:
        policy = verify_aer_policy(_policy_document())
        layout = _layout()
        classification = plan_guest_config_write(
            policy,
            layout,
            write_offset=layout.aer_capability_offset + 0x10,
            width=1,
            value=1,
        )
        executable = _bind_executable_write(
            classification,
            policy,
            layout,
            operation_id="single-consume-op",
            authority_revision=23,
        )
        self.assertEqual("single-consume-op", executable.operation_id)
        self.assertEqual(23, executable.authority_revision)
        self.assertEqual(1, executable.physical_write_count)
        self.assertFalse(executable.consumed)
        self.assertFalse(hasattr(executable, "physical_writes"))

        for operation_id, authority_revision in (
            ("other-operation", 23),
            ("single-consume-op", 24),
        ):
            with self.subTest(
                operation_id=operation_id,
                authority_revision=authority_revision,
            ):
                with self.assertRaises(
                    DirectPathVerificationError
                ) as stale_binding:
                    _consume_executable_write(
                        executable,
                        operation_id=operation_id,
                        authority_revision=authority_revision,
                    )
                self.assertEqual(
                    "AER_EXECUTABLE_WRITE_BINDING_MISMATCH",
                    stale_binding.exception.code,
                )
                self.assertFalse(executable.consumed)

        writes = _consume_executable_write(
            executable,
            operation_id="single-consume-op",
            authority_revision=23,
        )
        self.assertEqual(1, writes[0].value)
        self.assertTrue(executable.consumed)
        with self.assertRaises(DirectPathVerificationError) as replay:
            _consume_executable_write(
                executable,
                operation_id="single-consume-op",
                authority_revision=23,
            )
        self.assertEqual(
            "AER_EXECUTABLE_WRITE_PLAN_REPLAYED",
            replay.exception.code,
        )

    def test_reference_apply_cannot_replay_old_w1c_after_rearm(self) -> None:
        policy = verify_aer_policy(_policy_document())
        layout = _layout()
        dirty = AerReferenceModel.initial(
            policy=policy,
            route=CorrectableRouteControl(True, 0, True),
            endpoint_requester_id=0x101,
        ).inject_correctable(1, requester_id=0x101)
        cleared, consumed_plan = dirty.apply_guest_config_write(
            layout=layout,
            write_offset=layout.aer_capability_offset + 0x10,
            width=1,
            value=1,
            operation_id="reference-clear-op",
            authority_revision=29,
            **_current_layout_kwargs(layout),
        )
        self.assertEqual(0, cleared.physical.endpoint_correctable_status)
        self.assertTrue(consumed_plan.consumed)

        rearmed = cleared.inject_correctable(1, requester_id=0x101)
        self.assertEqual(1, rearmed.physical.endpoint_correctable_status)
        with self.assertRaises(DirectPathVerificationError) as replay:
            _consume_executable_write(
                consumed_plan,
                operation_id="reference-clear-op",
                authority_revision=29,
            )
        self.assertEqual(
            "AER_EXECUTABLE_WRITE_PLAN_REPLAYED",
            replay.exception.code,
        )
        self.assertEqual(1, rearmed.physical.endpoint_correctable_status)

    def test_uncorrectable_overlap_and_malformed_layout_fail_closed(self) -> None:
        policy = verify_aer_policy(_policy_document())
        plan = plan_guest_config_write(
            policy,
            _layout(),
            write_offset=0x18F,
            width=4,
            value=0xFFFFFFFF,
        )
        self.assertFalse(plan.physical_write_required)
        self.assertEqual(0xFFFFFFFF, plan.discarded_request_mask)
        self.assertEqual(
            (WriteDenyReason.UNCORRECTABLE_FIELD_FORBIDDEN,),
            plan.deny_reasons,
        )
        with self.assertRaises(DirectPathVerificationError):
            _layout(role=AerFunctionRole.ROOT_PORT, aer_offset=0xFE0)
        root_layout = _layout(role=AerFunctionRole.ROOT_PORT)
        self.assertIs(AerFunctionRole.ROOT_PORT, root_layout.function_role)
        invalid_bdf = dict(_layout().document)
        invalid_bdf["bdf"] = "0000:01:20.0"
        invalid_bdf["layoutDigest"] = None
        invalid_bdf["layoutDigest"] = sha256_digest(
            AER_CONFIG_LAYOUT_DIGEST_DOMAIN
            + canonical_json_bytes(invalid_bdf)
        )
        with self.assertRaises(DirectPathVerificationError):
            verify_aer_config_layout(invalid_bdf)
        with self.assertRaises(DirectPathVerificationError):
            plan_guest_config_write(
                policy,
                _layout(),
                write_offset=0x190,
                width=True,
                value=1,
            )

        write_only_clear = _policy_document()
        ces = write_only_clear["fields"]["CORRECTABLE_ERROR_STATUS"]
        ces["guestReadAllowMask"] = 1
        write_only_clear["aerPolicyDigest"] = None
        write_only_clear["aerPolicyDigest"] = sha256_digest(
            AER_POLICY_DIGEST_DOMAIN + canonical_json_bytes(write_only_clear)
        )
        with self.assertRaises(DirectPathVerificationError) as hidden_clear:
            verify_aer_policy(write_only_clear)
        self.assertEqual(
            "AER_W1C_MASK_NOT_READABLE",
            hidden_clear.exception.code,
        )

    def test_error_source_halves_are_classified_independently(self) -> None:
        policy = verify_aer_policy(_policy_document())
        layout = _layout(role=AerFunctionRole.ROOT_PORT)
        source_upper = project_guest_config_read(
            policy,
            layout,
            read_offset=layout.aer_capability_offset + 0x36,
            width=2,
            physical_field_values={
                AerField.ERROR_SOURCE_ID: 0xABCD,
            },
            shadow_field_values={},
            **_current_layout_kwargs(layout),
        )
        self.assertEqual(0, source_upper.value)
        self.assertEqual(
            (
                ReadLaneDisposition.UNCORRECTABLE_ZEROED,
                ReadLaneDisposition.UNCORRECTABLE_ZEROED,
            ),
            source_upper.lane_dispositions,
        )
        self.assertIsNone(source_upper.root_source_semantic_valid)
        self.assertIsNone(source_upper.root_source_semantic_requester_id)

        upper_write = plan_guest_config_write(
            policy,
            layout,
            write_offset=layout.aer_capability_offset + 0x36,
            width=2,
            value=0xFFFF,
        )
        self.assertFalse(upper_write.physical_write_required)
        self.assertEqual(0xFFFF, upper_write.discarded_request_mask)
        self.assertEqual(
            (WriteDenyReason.UNCORRECTABLE_FIELD_FORBIDDEN,),
            upper_write.deny_reasons,
        )

        cross_snapshot = project_guest_aer_snapshot(
            policy,
            layout,
            snapshot_id="m28-cross-half",
            authority_revision=17,
            physical_field_values={
                AerField.ROOT_ERROR_STATUS: 0,
                AerField.ERROR_SOURCE_ID: 0xABCD,
            },
            shadow_field_values={},
            **_current_layout_kwargs(layout),
        )
        cross_half = project_guest_config_read(
            policy,
            layout,
            read_offset=layout.aer_capability_offset + 0x35,
            width=2,
            physical_field_values={
                AerField.ERROR_SOURCE_ID: 0xABCD,
            },
            shadow_field_values={},
            root_snapshot=cross_snapshot,
            expected_root_snapshot_id="m28-cross-half",
            expected_root_snapshot_authority_revision=17,
            **_current_layout_kwargs(layout),
        )
        self.assertEqual(0x00AB, cross_half.value)
        self.assertEqual(
            (
                ReadLaneDisposition.PROJECTED,
                ReadLaneDisposition.UNCORRECTABLE_ZEROED,
            ),
            cross_half.lane_dispositions,
        )
        cross_write = plan_guest_config_write(
            policy,
            layout,
            write_offset=layout.aer_capability_offset + 0x35,
            width=2,
            value=0xFFFF,
        )
        self.assertFalse(cross_write.physical_write_required)
        self.assertEqual(0xFFFF, cross_write.discarded_request_mask)
        self.assertEqual(
            (WriteDenyReason.UNCORRECTABLE_FIELD_FORBIDDEN,),
            cross_write.deny_reasons,
        )

    def test_aer_mandatory_extent_and_next_pointer_are_exact(self) -> None:
        endpoint_at_last_valid_base = _layout(aer_offset=0xFD4)
        self.assertEqual(
            0xFD4,
            endpoint_at_last_valid_base.aer_capability_offset,
        )
        with self.assertRaises(DirectPathVerificationError) as overflow:
            _layout(aer_offset=0xFE8)
        self.assertEqual("AER_CONFIG_LAYOUT_INVALID", overflow.exception.code)

        hidden = verify_aer_policy(
            _policy_document(header="HIDDEN", body="VISIBLE")
        )
        with self.assertRaises(DirectPathVerificationError) as direct_overflow:
            project_hidden_ext_cap_chain(
                hidden,
                function_role=AerFunctionRole.ENDPOINT,
                predecessor_offset=0x140,
                predecessor_header=(0xFE8 << 20) | 0x00010010,
                aer_capability_offset=0xFE8,
                aer_header=0x00010001,
            )
        self.assertEqual(
            "AER_CONFIG_LAYOUT_INVALID",
            direct_overflow.exception.code,
        )

        inner_successor = dict(_layout().document)
        inner_successor["aerCapabilityHeader"] = (
            (0x184 << 20) | 0x00010001
        )
        inner_successor["layoutDigest"] = None
        inner_successor["layoutDigest"] = sha256_digest(
            AER_CONFIG_LAYOUT_DIGEST_DOMAIN
            + canonical_json_bytes(inner_successor)
        )
        with self.assertRaises(DirectPathVerificationError) as inner:
            verify_aer_config_layout(inner_successor)
        self.assertEqual("AER_CONFIG_LAYOUT_INVALID", inner.exception.code)

        with self.assertRaises(DirectPathVerificationError) as direct_inner:
            project_hidden_ext_cap_chain(
                hidden,
                function_role=AerFunctionRole.ENDPOINT,
                predecessor_offset=0x140,
                predecessor_header=(0x180 << 20) | 0x00010010,
                aer_capability_offset=0x180,
                aer_header=(0x184 << 20) | 0x00010001,
            )
        self.assertEqual(
            "AER_CONFIG_LAYOUT_INVALID",
            direct_inner.exception.code,
        )

    def test_hidden_first_aer_with_successor_fails_closed(self) -> None:
        hidden = verify_aer_policy(
            _policy_document(header="HIDDEN", body="VISIBLE")
        )
        first_document = dict(_layout().document)
        first_document.update(
            {
                "aerCapabilityOffset": 0x100,
                "aerCapabilityHeader": (0x200 << 20) | 0x00010001,
                "aerPredecessorOffsetOrNull": None,
                "aerPredecessorHeaderOrNull": None,
                "layoutDigest": None,
            }
        )
        first_document["layoutDigest"] = sha256_digest(
            AER_CONFIG_LAYOUT_DIGEST_DOMAIN
            + canonical_json_bytes(first_document)
        )
        first_with_successor = verify_aer_config_layout(first_document)
        with self.assertRaises(DirectPathVerificationError) as hidden_chain:
            project_guest_config_read(
                hidden,
                first_with_successor,
                read_offset=0x100,
                width=4,
                physical_field_values={},
                shadow_field_values={},
                **_current_layout_kwargs(first_with_successor),
            )
        self.assertEqual(
            "AER_HIDDEN_CHAIN_UNREPRESENTABLE",
            hidden_chain.exception.code,
        )

        terminal_document = dict(first_document)
        terminal_document["aerCapabilityHeader"] = 0x00010001
        terminal_document["layoutDigest"] = None
        terminal_document["layoutDigest"] = sha256_digest(
            AER_CONFIG_LAYOUT_DIGEST_DOMAIN
            + canonical_json_bytes(terminal_document)
        )
        terminal_first = verify_aer_config_layout(terminal_document)
        terminal_projection = project_guest_config_read(
            hidden,
            terminal_first,
            read_offset=0x100,
            width=4,
            physical_field_values={},
            shadow_field_values={},
            **_current_layout_kwargs(terminal_first),
        )
        self.assertEqual(0, terminal_projection.value)
        self.assertTrue(
            all(
                item is ReadLaneDisposition.HIDDEN_ZEROED
                for item in terminal_projection.lane_dispositions
            )
        )

    def test_header_body_projection_and_chain_rewire_are_orthogonal(self) -> None:
        header_hidden_body_visible = verify_aer_policy(
            _policy_document(header="HIDDEN", body="VISIBLE")
        )
        self.assertEqual(
            0,
            project_guest_read(
                header_hidden_body_visible,
                AerField.EXT_CAP_HEADER,
                physical_value=0x20010001,
            ),
        )
        self.assertEqual(
            0x41,
            project_guest_read(
                header_hidden_body_visible,
                AerField.CORRECTABLE_ERROR_STATUS,
                physical_value=0x41,
            ),
        )
        projection = project_hidden_ext_cap_chain(
            header_hidden_body_visible,
            function_role=AerFunctionRole.ENDPOINT,
            predecessor_offset=0x140,
            predecessor_header=(0x180 << 20) | 0x00010010,
            aer_capability_offset=0x180,
            aer_header=(0x200 << 20) | 0x00010001,
        )
        self.assertEqual(0x200, projection.successor_offset)
        self.assertEqual(0x200, projection.projected_predecessor_header >> 20)
        self.assertEqual(0, projection.projected_aer_header)

        hidden_zero = verify_aer_policy(
            _policy_document(
                header="HIDDEN",
                body="HIDDEN",
                hidden_read="ZERO",
                physical_writes=False,
            )
        )
        self.assertEqual(
            0,
            project_guest_read(
                hidden_zero,
                AerField.CORRECTABLE_ERROR_STATUS,
                physical_value=0x41,
                shadow_value=1,
            ),
        )
        hidden_shadow = verify_aer_policy(
            _policy_document(
                header="HIDDEN",
                body="HIDDEN",
                hidden_read="SHADOW",
                physical_writes=False,
            )
        )
        self.assertEqual(
            1,
            project_guest_read(
                hidden_shadow,
                AerField.CORRECTABLE_ERROR_STATUS,
                physical_value=0x41,
                shadow_value=1,
            ),
        )
        shadow_plan = plan_guest_config_write(
            hidden_shadow,
            _layout(),
            write_offset=0x190,
            width=1,
            value=0xFF,
        )
        self.assertFalse(shadow_plan.physical_write_required)
        self.assertEqual(0xC1, shadow_plan.shadow_w1c[0].value)

    def test_verified_policy_and_plan_cannot_be_publicly_forged_or_mutated(self) -> None:
        document = _policy_document()
        policy = verify_aer_policy(document)
        with self.assertRaises(TypeError):
            VerifiedAerPolicy()
        with self.assertRaises(TypeError):
            replace(policy)
        with self.assertRaises(TypeError):
            policy.document["fields"]["CORRECTABLE_ERROR_STATUS"][
                "physicalW1cAllowMask"
            ] = 0
        plan = plan_guest_config_write(
            policy,
            _layout(),
            write_offset=0x190,
            width=1,
            value=1,
        )
        with self.assertRaises(TypeError):
            VerifiedGuestConfigWritePlan()
        with self.assertRaises(TypeError):
            replace(plan)
        with self.assertRaises(TypeError):
            VerifiedExecutableAerWritePlan()
        with self.assertRaises(TypeError):
            VerifiedExecutableAerWritePlan._construct()


class M29EvidenceQualificationAdmissionTests(unittest.TestCase):
    def test_qualified_claim_without_trusted_e4_is_structural_only(self) -> None:
        policy = verify_aer_policy(_policy_document())
        evidence = verify_aer_evidence(policy, _evidence_document(policy))
        document = _qualification_document(policy, evidence)
        structural = verify_aer_qualification(policy, evidence, document)
        self.assertFalse(structural.closure_structurally_valid)
        self.assertIsNone(structural.e4_replay_receipt)
        self.assertFalse(structural.component_authority)
        with self.assertRaises(TypeError):
            VerifiedAerQualification._construct(component_authority=True)

        with self.assertRaises(DirectPathVerificationError) as legacy:
            verify_aer_qualification(
                policy,
                evidence,
                document,
                evidence_verifier=LegacyNoneAerE4Verifier(),
                verification_nonce="aer-e4-nonce-1",
                authority_revision=17,
                evaluated_at=NOW,
            )
        self.assertEqual(
            "AER_QUALIFICATION_E4_RESOLVER_INVALID",
            legacy.exception.code,
        )

        qualification_document, request, receipt = _e4_replay_fixture(
            policy,
            evidence,
        )
        resolver = ReceiptResolver(receipt)
        qualification = verify_aer_qualification(
            policy,
            evidence,
            qualification_document,
            evidence_verifier=resolver,
            verification_nonce=request.verification_nonce,
            authority_revision=request.authority_revision,
            evaluated_at=request.evaluated_at,
        )
        self.assertTrue(qualification.closure_structurally_valid)
        self.assertFalse(qualification.component_authority)
        self.assertIsNotNone(qualification.e4_replay_receipt)
        self.assertEqual(1, len(resolver.calls))
        call = resolver.calls[0]
        self.assertIs(request.__class__, call["request"].__class__)
        self.assertEqual(
            qualification_document["e4ReplayReceiptDigest"],
            call["expected_receipt_digest"],
        )

        receipt["owner"]["assignmentId"] = "mutated-after-return"
        self.assertEqual(
            "assignment-a",
            qualification.e4_replay_receipt.assignment_id,
        )

    def test_none_resolver_extra_hash_and_fake_receipt_never_authorize(self) -> None:
        policy = verify_aer_policy(_policy_document())
        evidence = verify_aer_evidence(policy, _evidence_document(policy))
        document, request, receipt = _e4_replay_fixture(policy, evidence)

        for result in (None, True, False):
            with self.subTest(resolver_result=result):
                with self.assertRaises(
                    DirectPathVerificationError
                ) as invalid_result:
                    verify_aer_qualification(
                        policy,
                        evidence,
                        document,
                        evidence_verifier=ReceiptResolver(result),
                        verification_nonce=request.verification_nonce,
                        authority_revision=request.authority_revision,
                        evaluated_at=request.evaluated_at,
                    )
                self.assertEqual(
                    "AER_QUALIFICATION_E4_RESOLVER_INVALID",
                    invalid_result.exception.code,
                )

        extra = _qualification_document(policy, evidence)
        extra["e4EvidenceHashes"].append(_hash("splice"))
        extra["e4EvidenceHashes"].sort()
        _rehash_qualification(extra)
        with self.assertRaises(DirectPathVerificationError) as extra_hash:
            verify_aer_qualification(policy, evidence, extra)
        self.assertEqual(
            "AER_RESOURCE_BUDGET_EXCEEDED",
            extra_hash.exception.code,
        )

        fake = verify_aer_qualification(
            policy,
            evidence,
            document,
            evidence_verifier=ReceiptResolver(receipt),
            verification_nonce=request.verification_nonce,
            authority_revision=request.authority_revision,
            evaluated_at=request.evaluated_at,
        )
        expectation = _expectation(policy, evidence, fake)
        decision = evaluate_aer_admission(
            policy=policy,
            evidence=evidence,
            qualification=fake,
            expectation=expectation,
            runtime_gate=_runtime_gate(expectation),
            checked_at=NOW,
        )
        self.assertFalse(decision.component_eligible)
        self.assertIn(
            AerAdmissionDenyReason.TRUSTED_E4_ADAPTER_REQUIRED,
            decision.deny_reasons,
        )

    def test_e4_receipt_stale_splice_result_and_replay_fail_closed(self) -> None:
        policy = verify_aer_policy(_policy_document())
        evidence = verify_aer_evidence(policy, _evidence_document(policy))

        mutations = {
            "stale": lambda receipt: receipt.__setitem__(
                "validUntil",
                (NOW - timedelta(microseconds=1)).strftime(
                    "%Y-%m-%dT%H:%M:%S.%fZ"
                ),
            ),
            "digest-splice": lambda receipt: receipt[
                "caseResults"
            ][0].__setitem__("runResultDigest", _hash("spliced-run")),
            "result-mismatch": lambda receipt: receipt.__setitem__(
                "replayResult",
                "FAILED",
            ),
            "century-ttl": lambda receipt: receipt.__setitem__(
                "validUntil",
                datetime(2126, 7, 29, tzinfo=timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%S.%fZ"
                ),
            ),
        }
        expected_codes = {
            "stale": "AER_E4_REPLAY_RECEIPT_STALE",
            "digest-splice": "AER_E4_REPLAY_BINDING_MISMATCH",
            "result-mismatch": "AER_E4_REPLAY_RESULT_MISMATCH",
            "century-ttl": "AER_RESOURCE_BUDGET_EXCEEDED",
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                document, request, receipt = _e4_replay_fixture(
                    policy,
                    evidence,
                )
                mutate(receipt)
                if name == "digest-splice":
                    receipt["caseResultsDigest"] = sha256_digest(
                        AER_E4_CASE_RESULTS_DOMAIN
                        + canonical_json_bytes(receipt["caseResults"])
                    )
                _rehash_e4_receipt(receipt)
                document["e4ReplayReceiptDigest"] = receipt["receiptDigest"]
                _rehash_qualification(document)
                with self.assertRaises(DirectPathVerificationError) as raised:
                    verify_aer_qualification(
                        policy,
                        evidence,
                        document,
                        evidence_verifier=ReceiptResolver(receipt),
                        verification_nonce=request.verification_nonce,
                        authority_revision=request.authority_revision,
                        evaluated_at=request.evaluated_at,
                    )
                self.assertEqual(expected_codes[name], raised.exception.code)

        replay_document, old_request, old_receipt = _e4_replay_fixture(
            policy,
            evidence,
            verification_nonce="aer-e4-nonce-old",
            authority_revision=17,
        )
        for nonce, revision in (
            ("aer-e4-nonce-new", 17),
            ("aer-e4-nonce-old", 18),
        ):
            with self.subTest(nonce=nonce, revision=revision):
                with self.assertRaises(
                    DirectPathVerificationError
                ) as replayed:
                    verify_aer_qualification(
                        policy,
                        evidence,
                        replay_document,
                        evidence_verifier=ReceiptResolver(old_receipt),
                        verification_nonce=nonce,
                        authority_revision=revision,
                        evaluated_at=old_request.evaluated_at,
                    )
                self.assertEqual(
                    "AER_E4_REPLAY_BINDING_MISMATCH",
                    replayed.exception.code,
                )

    def test_e4_receipt_binds_every_current_identity_coordinate(self) -> None:
        policy = verify_aer_policy(_policy_document())
        evidence = verify_aer_evidence(policy, _evidence_document(policy))
        mutations = {
            "policy": lambda receipt: receipt.__setitem__(
                "aerPolicyDigest",
                _hash("other-policy"),
            ),
            "layout": lambda receipt: receipt.__setitem__(
                "layoutDigest",
                _hash("other-layout"),
            ),
            "device": lambda receipt: receipt["device"].__setitem__(
                "identityDigest",
                _hash("other-device"),
            ),
            "owner": lambda receipt: receipt["owner"].__setitem__(
                "assignmentId",
                "assignment-b",
            ),
            "lease-generation": lambda receipt: receipt[
                "owner"
            ].__setitem__("leaseGeneration", 8),
            "owner-epoch": lambda receipt: receipt["owner"].__setitem__(
                "ownerEpoch",
                12,
            ),
            "host-boot": lambda receipt: receipt["owner"].__setitem__(
                "hostBootId",
                "boot-b",
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                document, request, receipt = _e4_replay_fixture(
                    policy,
                    evidence,
                )
                mutate(receipt)
                _rehash_e4_receipt(receipt)
                document["e4ReplayReceiptDigest"] = receipt["receiptDigest"]
                _rehash_qualification(document)
                with self.assertRaises(DirectPathVerificationError) as raised:
                    verify_aer_qualification(
                        policy,
                        evidence,
                        document,
                        evidence_verifier=ReceiptResolver(receipt),
                        verification_nonce=request.verification_nonce,
                        authority_revision=request.authority_revision,
                        evaluated_at=request.evaluated_at,
                    )
                self.assertEqual(
                    "AER_E4_REPLAY_BINDING_MISMATCH",
                    raised.exception.code,
                )

    def test_runtime_oracle_containment_and_case_results_are_independent(self) -> None:
        policy = verify_aer_policy(_policy_document())
        for mutation in ("containment", "case"):
            with self.subTest(mutation=mutation):
                document = _evidence_document(policy)
                if mutation == "containment":
                    document["containmentExact"] = False
                else:
                    document["caseResults"][2]["result"] = "INCONCLUSIVE"
                document["evidenceDigest"] = None
                document["evidenceDigest"] = sha256_digest(
                    AER_EVIDENCE_DIGEST_DOMAIN
                    + canonical_json_bytes(document)
                )
                evidence = verify_aer_evidence(policy, document)
                self.assertFalse(evidence.behavior_authority)
                qualification = verify_aer_qualification(
                    policy,
                    evidence,
                    _qualification_document(
                        policy,
                        evidence,
                        result="INCONCLUSIVE",
                    ),
                )
                self.assertFalse(qualification.component_authority)

    def test_policy_evidence_and_qualification_digest_tamper_fail(self) -> None:
        policy_document = _policy_document()
        policy_document["policyId"] = "tampered"
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_aer_policy(policy_document)
        self.assertEqual("AER_POLICY_DIGEST_INVALID", raised.exception.code)

        policy = verify_aer_policy(_policy_document())
        evidence_document = _evidence_document(policy)
        evidence_document["binding"]["gate"] = "g100"
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_aer_evidence(policy, evidence_document)
        self.assertEqual("AER_EVIDENCE_DIGEST_INVALID", raised.exception.code)

        evidence = verify_aer_evidence(policy, _evidence_document(policy))
        qualification_document = _qualification_document(policy, evidence)
        qualification_document["caseIds"] = list(AER_REQUIRED_CASE_IDS[:-1])
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_aer_qualification(
                policy,
                evidence,
                qualification_document,
            )
        self.assertEqual(
            "AER_QUALIFICATION_CASES_INCOMPLETE",
            raised.exception.code,
        )

    def test_candidate_inconclusive_and_nested_cannot_gain_authority(self) -> None:
        policy = verify_aer_policy(_policy_document())
        for classification in (
            AerEvidenceClassification.CANDIDATE.value,
            AerEvidenceClassification.INCONCLUSIVE.value,
        ):
            with self.subTest(classification=classification):
                evidence = verify_aer_evidence(
                    policy,
                    _evidence_document(policy, classification=classification),
                )
                self.assertFalse(evidence.behavior_authority)
                qualification = verify_aer_qualification(
                    policy,
                    evidence,
                    _qualification_document(
                        policy,
                        evidence,
                        result=AerQualificationResult.INCONCLUSIVE.value,
                    ),
                )
                self.assertFalse(qualification.component_authority)
                forged = _qualification_document(policy, evidence)
                with self.assertRaises(DirectPathVerificationError):
                    verify_aer_qualification(policy, evidence, forged)

        nested = verify_aer_evidence(
            policy,
            _evidence_document(policy, environment_kind="NESTED"),
        )
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_aer_qualification(
                policy,
                nested,
                _qualification_document(policy, nested),
            )
        self.assertEqual(
            "AER_QUALIFICATION_AUTHORITY_INVALID",
            raised.exception.code,
        )

    def test_default_and_structural_e4_both_deny_without_product_adapter(self) -> None:
        default = evaluate_aer_admission()
        self.assertFalse(default.component_eligible)
        self.assertFalse(default.product_authorized)
        self.assertEqual(
            (AerAdmissionDenyReason.MISSING_INPUT,),
            default.deny_reasons,
        )

        policy, evidence, qualification = _verified_chain()
        expectation = _expectation(policy, evidence, qualification)
        decision = evaluate_aer_admission(
            policy=policy,
            evidence=evidence,
            qualification=qualification,
            expectation=expectation,
            runtime_gate=_runtime_gate(expectation),
            checked_at=NOW,
        )
        self.assertFalse(decision.component_eligible)
        self.assertFalse(decision.product_authorized)
        self.assertIn(
            AerAdmissionDenyReason.TRUSTED_E4_ADAPTER_REQUIRED,
            decision.deny_reasons,
        )
        self.assertEqual(AER_AUTHORITY_BOUNDARY, decision.authority_boundary)
        projection = decision.to_subject()
        projection["assessmentDigest"] = None
        self.assertEqual(
            decision.assessment_digest,
            sha256_digest(
                AER_ADMISSION_ASSESSMENT_DOMAIN
                + canonical_json_bytes(projection)
            ),
        )
        with self.assertRaises(TypeError):
            type(decision)()

    def test_expired_authority_and_layout_change_cannot_reuse_old_match(self) -> None:
        policy, evidence, qualification = _verified_chain()
        expectation = _expectation(policy, evidence, qualification)
        expired = AerRuntimeGate(
            cleanup_verified=True,
            reuse_gate_passed=True,
            reset_scope_clean=True,
            quarantined=False,
            layout_digest=expectation.layout_digest,
            current_authority_vector_digest=(
                expectation.current_authority_vector_digest
            ),
            observed_at=NOW - timedelta(seconds=30),
            valid_until=NOW - timedelta(seconds=1),
        )
        expired_decision = evaluate_aer_admission(
            policy=policy,
            evidence=evidence,
            qualification=qualification,
            expectation=expectation,
            runtime_gate=expired,
            checked_at=NOW,
        )
        self.assertIn(
            AerAdmissionDenyReason.STALE_AUTHORITY_REJECTED,
            expired_decision.deny_reasons,
        )

        new_layout_digest = _hash("new-layout")
        changed_expectation = replace(
            expectation,
            layout_digest=new_layout_digest,
        )
        changed_gate = AerRuntimeGate(
            cleanup_verified=True,
            reuse_gate_passed=True,
            reset_scope_clean=True,
            quarantined=False,
            layout_digest=new_layout_digest,
            current_authority_vector_digest=(
                expectation.current_authority_vector_digest
            ),
            observed_at=NOW - timedelta(seconds=1),
            valid_until=NOW + timedelta(seconds=30),
        )
        changed = evaluate_aer_admission(
            policy=policy,
            evidence=evidence,
            qualification=qualification,
            expectation=changed_expectation,
            runtime_gate=changed_gate,
            checked_at=NOW,
        )
        self.assertIn(
            AerAdmissionDenyReason.OBSERVATION_BINDING_MISMATCH,
            changed.deny_reasons,
        )

    def test_unknown_dimensions_cleanup_reuse_reset_and_quarantine_deny(self) -> None:
        policy = verify_aer_policy(_policy_document())
        unknown_evidence = verify_aer_evidence(
            policy,
            _evidence_document(policy, dimension_result="UNKNOWN"),
        )
        unknown_qualification = verify_aer_qualification(
            policy,
            unknown_evidence,
            _qualification_document(
                policy,
                unknown_evidence,
                result="INCONCLUSIVE",
            ),
        )
        unknown_expectation = _expectation(
            policy,
            unknown_evidence,
            unknown_qualification,
        )
        unknown_decision = evaluate_aer_admission(
            policy=policy,
            evidence=unknown_evidence,
            qualification=unknown_qualification,
            expectation=unknown_expectation,
            runtime_gate=_runtime_gate(unknown_expectation),
            checked_at=NOW,
        )
        self.assertIn(
            AerAdmissionDenyReason.DIMENSION_UNVERIFIED,
            unknown_decision.deny_reasons,
        )
        self.assertEqual(tuple(AerDimension), unknown_decision.unverified_dimensions)

        policy, evidence, qualification = _verified_chain()
        expectation = _expectation(policy, evidence, qualification)
        gate = _runtime_gate(
            expectation,
            cleanup=False,
            reuse=False,
            reset_clean=False,
            quarantined=True,
        )
        decision = evaluate_aer_admission(
            policy=policy,
            evidence=evidence,
            qualification=qualification,
            expectation=expectation,
            runtime_gate=gate,
            checked_at=NOW,
        )
        self.assertFalse(decision.component_eligible)
        self.assertIn(
            AerAdmissionDenyReason.LIFECYCLE_CLEANUP_UNVERIFIED,
            decision.deny_reasons,
        )
        self.assertIn(
            AerAdmissionDenyReason.REUSE_GATE_NOT_PASSED,
            decision.deny_reasons,
        )
        self.assertIn(
            AerAdmissionDenyReason.RESET_SCOPE_UNCLEAN,
            decision.deny_reasons,
        )
        self.assertIn(
            AerAdmissionDenyReason.DEVICE_QUARANTINED,
            decision.deny_reasons,
        )

    def test_structural_current_receipt_is_exact_frozen_and_never_authority(
        self,
    ) -> None:
        policy, evidence, qualification = _verified_chain()
        expectation = _expectation(policy, evidence, qualification)
        request, gate, receipt_document = (
            _admission_current_receipt_fixture(
                policy,
                evidence,
                qualification,
                expectation,
            )
        )
        receipt = verify_structural_aer_admission_current_receipt(
            request,
            receipt_document,
            expected_receipt_digest=receipt_document["receiptDigest"],
        )
        self.assertFalse(receipt.component_authority)
        self.assertEqual(request.request_digest, receipt.request_digest)
        self.assertEqual(18, receipt.committed_authority_revision)

        decision = evaluate_aer_admission(
            policy=policy,
            evidence=evidence,
            qualification=qualification,
            expectation=expectation,
            runtime_gate=gate,
            checked_at=NOW,
            current_request=request,
            current_receipt=receipt,
        )
        self.assertFalse(decision.component_eligible)
        self.assertFalse(decision.product_authorized)
        self.assertNotIn(
            AerAdmissionDenyReason.CURRENT_AUTHORITY_RECEIPT_REQUIRED,
            decision.deny_reasons,
        )
        self.assertNotIn(
            AerAdmissionDenyReason.CURRENT_AUTHORITY_RECEIPT_MISMATCH,
            decision.deny_reasons,
        )
        self.assertIn(
            AerAdmissionDenyReason.TRUSTED_E4_ADAPTER_REQUIRED,
            decision.deny_reasons,
        )
        self.assertEqual(
            receipt.receipt_digest,
            decision.current_receipt_digest,
        )

        receipt_document["owner"]["assignmentId"] = "toctou-mutation"
        receipt_document["sourceHashes"].append(
            {"sourceId": "toctou", "sha256": _hash("toctou")}
        )
        self.assertEqual(
            "assignment-a",
            receipt.document["owner"]["assignmentId"],
        )
        self.assertEqual(2, len(receipt.document["sourceHashes"]))
        with self.assertRaises(TypeError):
            receipt.document["owner"]["assignmentId"] = "forbidden"

    def test_fake_current_receipt_and_request_objects_fail_closed(self) -> None:
        with self.assertRaises(TypeError):
            VerifiedAerEvidence._construct()
        with self.assertRaises(TypeError):
            AerE4ReplayRequest._construct()
        with self.assertRaises(TypeError):
            VerifiedAerE4ReplayReceipt._construct()
        with self.assertRaises(TypeError):
            AerAdmissionCurrentRequest._construct()
        with self.assertRaises(TypeError):
            VerifiedStructuralAerAdmissionCurrentReceipt._construct()

        policy, evidence, qualification = _verified_chain()
        expectation = _expectation(policy, evidence, qualification)
        with self.assertRaises(DirectPathVerificationError) as raised:
            evaluate_aer_admission(
                policy=policy,
                evidence=evidence,
                qualification=qualification,
                expectation=expectation,
                runtime_gate=_runtime_gate(expectation),
                checked_at=NOW,
                current_request=object(),
                current_receipt=object(),
            )
        self.assertEqual(
            "AER_ADMISSION_CURRENT_REQUEST_INVALID",
            raised.exception.code,
        )

    def test_current_receipt_clock_ttl_and_numeric_budgets_fail_closed(
        self,
    ) -> None:
        policy, evidence, qualification = _verified_chain()
        expectation = _expectation(policy, evidence, qualification)
        request, gate, receipt_document = (
            _admission_current_receipt_fixture(
                policy,
                evidence,
                qualification,
                expectation,
            )
        )
        receipt = verify_structural_aer_admission_current_receipt(
            request,
            receipt_document,
            expected_receipt_digest=receipt_document["receiptDigest"],
        )
        stale_clock = evaluate_aer_admission(
            policy=policy,
            evidence=evidence,
            qualification=qualification,
            expectation=expectation,
            runtime_gate=gate,
            checked_at=NOW - timedelta(microseconds=1),
            current_request=request,
            current_receipt=receipt,
        )
        self.assertIn(
            AerAdmissionDenyReason.STALE_AUTHORITY_REJECTED,
            stale_clock.deny_reasons,
        )

        future_observation = copy.deepcopy(receipt_document)
        future_observation["runtimeGate"]["observedAt"] = (
            NOW + timedelta(seconds=1)
        ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        _rehash_admission_current_receipt(future_observation)
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_structural_aer_admission_current_receipt(
                request,
                future_observation,
                expected_receipt_digest=future_observation["receiptDigest"],
            )
        self.assertEqual(
            "AER_ADMISSION_CURRENT_RECEIPT_STALE",
            raised.exception.code,
        )

        with self.assertRaises(DirectPathVerificationError) as raised:
            AerRuntimeGate(
                cleanup_verified=True,
                reuse_gate_passed=True,
                reset_scope_clean=True,
                quarantined=False,
                layout_digest=expectation.layout_digest,
                current_authority_vector_digest=(
                    expectation.current_authority_vector_digest
                ),
                observed_at=NOW,
                valid_until=(
                    NOW
                    + AER_ADMISSION_MAX_RUNTIME_GATE_TTL
                    + timedelta(microseconds=1)
                ),
            )
        self.assertEqual("AER_RESOURCE_BUDGET_EXCEEDED", raised.exception.code)

        for invalid_revision in (float("nan"), float("inf")):
            with self.subTest(invalid_revision=invalid_revision):
                with self.assertRaises(DirectPathVerificationError):
                    prepare_aer_admission_current_request(
                        policy,
                        evidence,
                        qualification,
                        expectation,
                        verification_nonce="admission-current-nonce-0002",
                        authority_revision=invalid_revision,
                        requested_at=NOW,
                    )

    def test_current_receipt_vector_nonce_revision_replay_and_splice_deny(
        self,
    ) -> None:
        policy, evidence, qualification = _verified_chain()
        expectation = _expectation(policy, evidence, qualification)
        request, gate, receipt_document = (
            _admission_current_receipt_fixture(
                policy,
                evidence,
                qualification,
                expectation,
            )
        )
        receipt = verify_structural_aer_admission_current_receipt(
            request,
            receipt_document,
            expected_receipt_digest=receipt_document["receiptDigest"],
        )
        structural_replay = verify_structural_aer_admission_current_receipt(
            request,
            receipt.canonical_bytes,
            expected_receipt_digest=receipt.receipt_digest,
        )
        self.assertFalse(structural_replay.component_authority)
        self.assertEqual(receipt.receipt_digest, structural_replay.receipt_digest)

        for name, mutate in (
            (
                "vector",
                lambda document: (
                    document.__setitem__(
                        "currentAuthorityVectorDigest",
                        _hash("spliced-vector"),
                    ),
                    document["runtimeGate"].__setitem__(
                        "currentAuthorityVectorDigest",
                        _hash("spliced-vector"),
                    ),
                ),
            ),
            (
                "nonce",
                lambda document: (
                    document.__setitem__(
                        "verificationNonce",
                        "admission-current-nonce-splice",
                    ),
                    document["cas"].__setitem__(
                        "nonce",
                        "admission-current-nonce-splice",
                    ),
                ),
            ),
            (
                "revision",
                lambda document: (
                    document.__setitem__("authorityRevision", 18),
                    document["cas"].__setitem__(
                        "expectedAuthorityRevision",
                        18,
                    ),
                    document["cas"].__setitem__(
                        "committedAuthorityRevision",
                        19,
                    ),
                ),
            ),
        ):
            with self.subTest(name=name):
                spliced = copy.deepcopy(receipt_document)
                mutate(spliced)
                _rehash_admission_current_receipt(spliced)
                with self.assertRaises(DirectPathVerificationError):
                    verify_structural_aer_admission_current_receipt(
                        request,
                        spliced,
                        expected_receipt_digest=spliced["receiptDigest"],
                    )

        new_request = prepare_aer_admission_current_request(
            policy,
            evidence,
            qualification,
            expectation,
            verification_nonce="admission-current-nonce-0003",
            authority_revision=18,
            requested_at=NOW - timedelta(seconds=2),
        )
        with self.assertRaises(DirectPathVerificationError):
            verify_structural_aer_admission_current_receipt(
                new_request,
                receipt.canonical_bytes,
                expected_receipt_digest=receipt.receipt_digest,
            )

        changed_expectation = replace(
            expectation,
            current_authority_vector_digest=_hash("new-current-vector"),
        )
        changed_gate = replace(
            gate,
            current_authority_vector_digest=_hash("new-current-vector"),
        )
        decision = evaluate_aer_admission(
            policy=policy,
            evidence=evidence,
            qualification=qualification,
            expectation=changed_expectation,
            runtime_gate=changed_gate,
            checked_at=NOW,
            current_request=request,
            current_receipt=receipt,
        )
        self.assertIn(
            AerAdmissionDenyReason.CURRENT_AUTHORITY_RECEIPT_MISMATCH,
            decision.deny_reasons,
        )

    def test_source_case_hash_and_document_budget_bombs_rejected(self) -> None:
        policy, evidence, qualification = _verified_chain()
        expectation = _expectation(policy, evidence, qualification)
        oversized_sources = tuple(
            (f"source-{index:03d}", _hash(f"source-{index:03d}"))
            for index in range(AER_MAX_SOURCE_HASHES + 1)
        )
        with self.assertRaises(DirectPathVerificationError) as raised:
            replace(expectation, source_hashes=oversized_sources)
        self.assertEqual("AER_RESOURCE_BUDGET_EXCEEDED", raised.exception.code)

        request, _, receipt_document = _admission_current_receipt_fixture(
            policy,
            evidence,
            qualification,
            expectation,
        )
        for name, field, payload in (
            (
                "sources",
                "sourceHashes",
                [
                    {
                        "sourceId": f"source-{index:03d}",
                        "sha256": _hash(f"source-{index:03d}"),
                    }
                    for index in range(AER_MAX_SOURCE_HASHES + 1)
                ],
            ),
            (
                "cases",
                "caseResults",
                receipt_document["caseResults"]
                + [copy.deepcopy(receipt_document["caseResults"][-1])],
            ),
            (
                "hashes",
                "e4EvidenceHashes",
                [
                    _hash(f"hash-{index:03d}")
                    for index in range(AER_MAX_E4_EVIDENCE_HASHES + 1)
                ],
            ),
        ):
            with self.subTest(name=name):
                bomb = copy.deepcopy(receipt_document)
                bomb[field] = payload
                _rehash_admission_current_receipt(bomb)
                with self.assertRaises(DirectPathVerificationError) as raised:
                    verify_structural_aer_admission_current_receipt(
                        request,
                        bomb,
                        expected_receipt_digest=bomb["receiptDigest"],
                    )
                self.assertEqual(
                    "AER_RESOURCE_BUDGET_EXCEEDED",
                    raised.exception.code,
                )

        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_structural_aer_admission_current_receipt(
                request,
                b"{" + (b" " * AER_ADMISSION_MAX_RECEIPT_BYTES),
                expected_receipt_digest=_hash("oversized-receipt"),
            )
        self.assertEqual("AER_RESOURCE_BUDGET_EXCEEDED", raised.exception.code)

        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_structural_aer_admission_current_receipt(
                request,
                {"budgetBomb": "x" * AER_ADMISSION_MAX_RECEIPT_BYTES},
                expected_receipt_digest=_hash("oversized-mapping"),
            )
        self.assertEqual("AER_RESOURCE_BUDGET_EXCEEDED", raised.exception.code)

        huge_evidence = _evidence_document(policy)
        huge_evidence["budgetBomb"] = "x" * AER_MAX_DOCUMENT_BYTES
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_aer_evidence(policy, huge_evidence)
        self.assertEqual("AER_RESOURCE_BUDGET_EXCEEDED", raised.exception.code)


if __name__ == "__main__":
    unittest.main()
