"""Typed qualification-profile construction and static request binding.

The profile verifier consumes only verifier-produced trust/qualification
contexts plus exact closed documents.  Recursive E4 artifact resolution is an
explicit component replay port because this side-effect-free package has no
authenticated evidence repository.  A caller-provided or test-fake port is
useful only for component tests; it is not E4 product evidence, executable
provenance, a linearizable repository read, or product repository authority.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Protocol

from ._verified import FactoryVerified, require_factory_verified
from .admission import VerifiedStaticAdmissionContext
from .canonical import (
    CanonicalizationError,
    canonical_json_bytes,
    load_canonical_json,
    sha256_digest,
)
from .capability import AdmissionRequirement
from .contracts import ContractSchemas
from .errors import DirectPathVerificationError, fail, require
from .trust import (
    QualificationProfileDependency,
    VerifiedQualificationContext,
)


JsonDocument = Mapping[str, Any] | bytes | bytearray | memoryview

_ALGORITHM_DOMAIN = b"QMAN-DIRECTPATH/QUALIFICATION-PROFILE-VERIFIER-ALGORITHM/V1\x00"
_PROJECTION_DOMAIN = b"QMAN-DIRECTPATH/QUALIFICATION-PROFILE-PROJECTION/V1\x00"
_PROFILE_SEMANTICS_DOMAIN = b"QMAN-DIRECTPATH/QUALIFICATION-PROFILE-SEMANTICS/V1\x00"
_MACHINE_DOMAIN = b"QMAN-DIRECTPATH/QUALIFICATION-PROFILE-MACHINE/V1\x00"
_FIRMWARE_DOMAIN = b"QMAN-DIRECTPATH/QUALIFICATION-PROFILE-FIRMWARE/V1\x00"
_BACKEND_DOMAIN = b"QMAN-DIRECTPATH/QUALIFICATION-PROFILE-BACKEND/V1\x00"
_DEVICE_TRAITS_DOMAIN = b"QMAN-DIRECTPATH/QUALIFICATION-PROFILE-DEVICE-TRAITS/V1\x00"
_E4_CLOSURE_DOMAIN = b"QMAN-DIRECTPATH/QUALIFICATION-PROFILE-E4-CLOSURE/V1\x00"
_RECEIPT_DOMAIN = b"QMAN-DIRECTPATH/QUALIFICATION-VERIFICATION-RECEIPT/V1\x00"
_QUALIFICATION_PROFILE_FACTORY_TOKEN = object()
_STATIC_QUALIFICATION_BINDING_FACTORY_TOKEN = object()

QUALIFICATION_VERIFICATION_DISPOSITION = "STRUCTURALLY_VALID"
QUALIFICATION_AUTHORITY_BOUNDARY = "COMPONENT_ONLY"
TRUSTED_E4_ADAPTER_REQUIRED = "TRUSTED_E4_ADAPTER_REQUIRED"
_QUALIFICATION_AUTHORIZATION_BLOCKERS = (TRUSTED_E4_ADAPTER_REQUIRED,)

_PROFILE_SEMANTIC_FIELDS = (
    "profileId",
    "platformProfileId",
    "platformDigest",
    "kernelDigest",
    "qemuDigest",
    "machineDigest",
    "firmwareDigest",
    "backendDigest",
    "deviceTraitsDigest",
    "guestAbiClass",
    "workloadDigest",
    "revocationSeverity",
    "revocationBehavior",
    "supportStatus",
)
_PROFILE_SEMANTIC_EXCLUDED_FIELDS = (
    "qualificationRecordDigests",
    "supportedCatalogDigest",
    "catalogSequence",
    "verificationReceiptHash",
    "profileHash",
)

_SCHEMA_REFS = (
    "contracts/directpath-qualification-profile-projection.schema.json",
    "contracts/directpath-qualification-verification-receipt.schema.json",
    (
        "contracts/directpath-portable-hash-subjects.schema.json"
        "#/$defs/qualificationProfile"
    ),
    "contracts/directpath-qualification-record.schema.json",
    "contracts/directpath-supported-catalog.schema.json",
    "contracts/directpath-catalog-rollback-anchor.schema.json",
    "contracts/directpath-anchor-freshness-envelope.schema.json",
    "contracts/directpath-trust-root-set.schema.json",
    "contracts/directpath-trust-key-ring.schema.json",
    "contracts/directpath-trust-rollback-anchor.schema.json",
)


class QualificationEvidenceVerifier(Protocol):
    """Component port for recursive E4 artifact resolution and semantic replay.

    A production implementation must independently resolve every artifact,
    schema, signature and closure edge named by the QualificationRecord.  Mere
    conformance to this Python protocol, a successful return from a fake, or a
    matching digest does not constitute E4 product evidence or repository
    authority.
    """

    def verify_e4_closure(
        self,
        *,
        qualification_record_bytes: bytes,
        qualification_record_digest: str,
        exact_qualification_key: str,
        qualification_subject_manifest_digest: str,
        qualification_case_matrix_sha256: str,
        case_ids: tuple[str, ...],
        e4_evidence_hashes: tuple[str, ...],
        expected_e4_closure_digest: str,
        verified_at: datetime,
    ) -> None:
        """Resolve and replay the complete E4 closure or raise on failure."""


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _document(value: JsonDocument, path: str) -> tuple[dict[str, Any], bytes]:
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        try:
            loaded = load_canonical_json(raw)
        except CanonicalizationError as exc:
            fail("CANONICAL_JSON_INVALID", path, str(exc))
    elif isinstance(value, Mapping):
        try:
            raw = canonical_json_bytes(value)
            loaded = load_canonical_json(raw)
        except (
            CanonicalizationError,
            KeyError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as exc:
            fail("CANONICAL_JSON_INVALID", path, str(exc))
    else:
        fail(
            "DOCUMENT_TYPE_INVALID",
            path,
            "expected canonical JSON bytes or a JSON object",
        )
    require(
        isinstance(loaded, dict),
        "DOCUMENT_TYPE_INVALID",
        path,
        "expected a JSON object",
    )
    return loaded, raw


def _timestamp(value: str, path: str) -> datetime:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except (TypeError, ValueError) as exc:
        fail("TIME_INVALID", path, f"invalid contract timestamp: {exc}")
    return parsed.replace(tzinfo=timezone.utc)


def _timestamp_text(value: datetime) -> str:
    checked = value.astimezone(timezone.utc)
    return checked.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _domain_digest(domain: bytes, value: Any) -> str:
    return sha256_digest(domain + canonical_json_bytes(value))


def _schema_bindings(schemas: ContractSchemas) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for index, schema_ref in enumerate(_SCHEMA_REFS):
        file_ref = schema_ref.partition("#")[0]
        result.append(
            {
                "schemaRef": schema_ref,
                "schemaSha256": schemas.digest_for_ref(
                    file_ref,
                    path=f"qualificationProfile.schemaBindings[{index}]",
                ),
            }
        )
    return result


def _qualification_selectors(
    record: Mapping[str, Any],
) -> set[tuple[str, str]]:
    selectors: set[tuple[str, str]] = {
        ("QUALIFICATION_RECORD", record["recordDigest"]),
        (
            "PCI_IDENTITY",
            sha256_digest(canonical_json_bytes(record["pciIdentityMatch"])),
        ),
        ("PLATFORM_PROFILE", record["platformProfileHash"]),
    }
    firmware = record["deviceFirmwareAndRom"]
    for field_name in (
        "deviceFirmwareDigest",
        "optionRomDigestOrNull",
        "vpdDigestOrNull",
        "settingsDigest",
    ):
        digest = firmware[field_name]
        if digest is not None:
            selectors.add(("FIRMWARE", digest))
    workload = record["guestDriverAndWorkload"]
    selectors.add(("GUEST_DRIVER", workload["guestDriverDigest"]))
    selectors.add(("WORKLOAD", workload["workloadDefinitionDigest"]))
    return selectors


def _applicable_denies(
    record: Mapping[str, Any],
    catalog: Mapping[str, Any],
    *,
    verified_at: datetime,
) -> tuple[tuple[str, ...], datetime | None]:
    selectors = _qualification_selectors(record)
    applicable: list[tuple[str, datetime]] = []
    for index, entry in enumerate(catalog["denyAndRevocationEntries"]):
        selector = (entry["selectorKind"], entry["selectorDigest"])
        if selector not in selectors:
            continue
        effective_at = _timestamp(
            entry["effectiveAt"],
            (
                "qualificationProfile.catalog.denyAndRevocationEntries"
                f"[{index}].effectiveAt"
            ),
        )
        require(
            effective_at > verified_at,
            "QUALIFICATION_DENIED",
            (f"qualificationProfile.catalog.denyAndRevocationEntries[{index}]"),
            "an effective catalog deny cannot produce a supported profile",
        )
        applicable.append(
            (
                sha256_digest(canonical_json_bytes(entry)),
                effective_at,
            )
        )
    digests = tuple(sorted(item[0] for item in applicable))
    next_effective = min(item[1] for item in applicable) if applicable else None
    return digests, next_effective


def _profile_projection(
    record: Mapping[str, Any],
    catalog: Mapping[str, Any],
) -> dict[str, Any]:
    runtime = record["kernelQemuFirmwareBackend"]
    machine_digest = _domain_digest(
        _MACHINE_DOMAIN,
        {
            "machineType": runtime["machineType"],
            "machineVersion": runtime["machineVersion"],
        },
    )
    firmware_digest = _domain_digest(
        _FIRMWARE_DOMAIN,
        {
            "deviceFirmwareAndRom": record["deviceFirmwareAndRom"],
            "firmwareKind": runtime["firmwareKind"],
            "firmwareCodeDigest": runtime["firmwareCodeDigest"],
            "firmwareVarsBaseDigestOrNull": (runtime["firmwareVarsBaseDigestOrNull"]),
        },
    )
    backend_digest = _domain_digest(
        _BACKEND_DOMAIN,
        {
            "backendFamily": runtime["backendFamily"],
            "configuredIommuType": runtime["configuredIommuType"],
            "runtimeCapabilities": runtime["runtimeCapabilities"],
            "iommuInterruptResetProviders": (record["iommuInterruptResetProviders"]),
        },
    )
    traits_digest = _domain_digest(
        _DEVICE_TRAITS_DOMAIN,
        {"deviceTraits": record["deviceTraits"]},
    )
    behavior = catalog["revocationBehavior"]
    severity_by_behavior = {
        "DENY_NEW_AND_NEXT_POWER_ON": "NORMAL",
        "DENY_NEW_AND_REQUIRE_CONTROLLED_STOP": "CRITICAL",
    }
    try:
        severity = severity_by_behavior[behavior]
    except KeyError:
        fail(
            "QUALIFICATION_REVOCATION_BEHAVIOR_INVALID",
            "qualificationProfile.catalog.revocationBehavior",
            "catalog behavior has no closed severity projection",
        )
    return {
        "subjectType": "QUALIFICATION_PROFILE",
        "schemaVersion": 1,
        "profileId": record["exactQualificationKey"],
        "platformProfileId": runtime["platformProfileId"],
        "platformDigest": record["platformProfileHash"],
        "kernelDigest": runtime["kernelBuildDigest"],
        "qemuDigest": runtime["qemuBinaryDigest"],
        "machineDigest": machine_digest,
        "firmwareDigest": firmware_digest,
        "backendDigest": backend_digest,
        "deviceTraitsDigest": traits_digest,
        "guestAbiClass": record["guestDriverAndWorkload"]["guestAbiClass"],
        "workloadDigest": (
            record["guestDriverAndWorkload"]["workloadDefinitionDigest"]
        ),
        "qualificationRecordDigests": [record["recordDigest"]],
        "supportedCatalogDigest": catalog["catalogDigest"],
        "catalogSequence": catalog["catalogSequence"],
        "revocationSeverity": severity,
        "revocationBehavior": behavior,
        "supportStatus": "SUPPORTED",
    }


def _profile_semantic_projection(
    profile: Mapping[str, Any],
) -> dict[str, Any]:
    """Project owner-independent runtime/support semantics from a profile."""

    return {
        "subjectType": "QUALIFICATION_PROFILE_SEMANTICS",
        "schemaVersion": 1,
        **{field_name: profile[field_name] for field_name in _PROFILE_SEMANTIC_FIELDS},
    }


def _profile_semantic_digest(profile: Mapping[str, Any]) -> str:
    return _domain_digest(
        _PROFILE_SEMANTICS_DOMAIN,
        _profile_semantic_projection(profile),
    )


def _e4_closure(
    record: Mapping[str, Any],
) -> dict[str, Any]:
    projection = {
        "qualificationRecordDigest": record["recordDigest"],
        "qualificationSubjectManifestDigest": (
            record["qualificationSubjectManifestDigest"]
        ),
        "qualificationCaseMatrixSha256": (record["qualificationCaseMatrixSha256"]),
        "caseIds": record["caseIds"],
        "e4EvidenceHashes": record["e4EvidenceHashes"],
    }
    return {
        "qualificationSubjectManifestDigest": (
            record["qualificationSubjectManifestDigest"]
        ),
        "qualificationCaseMatrixSha256": (record["qualificationCaseMatrixSha256"]),
        "caseIds": copy.deepcopy(record["caseIds"]),
        "e4EvidenceHashes": copy.deepcopy(record["e4EvidenceHashes"]),
        "e4ClosureDigest": _domain_digest(_E4_CLOSURE_DOMAIN, projection),
    }


def _require_context_bindings(
    qualification: VerifiedQualificationContext,
    record: Mapping[str, Any],
    catalog: Mapping[str, Any],
) -> tuple[
    QualificationProfileDependency,
    Any,
    Any,
    datetime | None,
]:
    require(
        catalog["catalogId"] == qualification.catalog_id
        and catalog["catalogSequence"] == qualification.catalog_sequence
        and catalog["catalogDigest"] == qualification.catalog_digest,
        "QUALIFICATION_CATALOG_CONTEXT_MISMATCH",
        "qualificationProfile.catalog",
        "raw catalog does not exactly identify the verified current catalog",
    )
    catalog_members = tuple(catalog["qualificationRecordDigests"])
    context_members = tuple(
        sorted(
            profile.qualification_record_digest for profile in qualification.profiles
        )
    )
    require(
        catalog_members == context_members,
        "QUALIFICATION_CATALOG_CONTEXT_MISMATCH",
        "qualificationProfile.catalog.qualificationRecordDigests",
        "raw catalog membership does not equal the verified context",
    )
    dependency = qualification.profile(record["exactQualificationKey"])
    require(
        dependency.qualification_record_id == record["qualificationRecordId"]
        and dependency.qualification_record_digest == record["recordDigest"]
        and dependency.platform_profile_hash == record["platformProfileHash"],
        "QUALIFICATION_RECORD_CONTEXT_MISMATCH",
        "qualificationProfile.qualificationRecord",
        "raw record does not exactly identify the selected verified dependency",
    )
    trust = qualification.trust
    require(
        record["keyRingVersion"] == trust.key_ring_sequence
        and catalog["keyRingVersion"] == trust.key_ring_sequence,
        "QUALIFICATION_KEY_RING_BINDING_MISMATCH",
        "qualificationProfile",
        "record and catalog must bind the verified current key-ring sequence",
    )
    qe_key = trust.authorized_key(
        record["qualificationSignerKeyId"],
        required_role="QUALIFICATION_ENGINEERING",
        at=qualification.verified_at,
    )
    release_key = trust.authorized_key(
        catalog["productReleaseSignerKeyId"],
        required_role="PRODUCT_RELEASE",
        at=qualification.verified_at,
    )
    require(
        qe_key.key_id == dependency.qualification_signer_key_id
        and qe_key.principal_id == dependency.qualification_signer_principal_id,
        "QUALIFICATION_SIGNER_CONTEXT_MISMATCH",
        "qualificationProfile.qualificationRecord",
        "record signer does not replay from the verified dependency",
    )
    require(
        release_key.key_id == qualification.product_release_signer_key_id
        and release_key.principal_id
        == qualification.product_release_signer_principal_id,
        "QUALIFICATION_SIGNER_CONTEXT_MISMATCH",
        "qualificationProfile.catalog",
        "catalog signer does not replay from the verified context",
    )
    applicable_digests, next_deny = _applicable_denies(
        record,
        catalog,
        verified_at=qualification.verified_at,
    )
    require(
        applicable_digests == dependency.applicable_deny_entry_digests,
        "QUALIFICATION_DENY_CONTEXT_MISMATCH",
        "qualificationProfile.catalog.denyAndRevocationEntries",
        "applicable deny set does not replay from the verified dependency",
    )
    return dependency, qe_key, release_key, next_deny


def _validity_window(
    qualification: VerifiedQualificationContext,
    dependency: QualificationProfileDependency,
    record: Mapping[str, Any],
    catalog: Mapping[str, Any],
    qe_key: Any,
    release_key: Any,
    next_deny: datetime | None,
) -> tuple[datetime, datetime]:
    trust = qualification.trust
    current_ring = trust._rings[-1]
    require(
        qe_key.revoked_at is None and release_key.revoked_at is None,
        "QUALIFICATION_PROFILE_SCHEMA_BINDING_INCOMPLETE",
        "qualificationProfile.validity",
        (
            "the V1 receipt has no signer-revokedAt field; a signer with "
            "scheduled revocation is rejected instead of dropping that "
            "validity horizon"
        ),
    )
    record_not_before = _timestamp(
        record["notBefore"],
        "qualificationProfile.qualificationRecord.notBefore",
    )
    record_expires = _timestamp(
        record["expiresAt"],
        "qualificationProfile.qualificationRecord.expiresAt",
    )
    catalog_not_before = _timestamp(
        catalog["notBefore"],
        "qualificationProfile.catalog.notBefore",
    )
    catalog_expires = _timestamp(
        catalog["expiresAt"],
        "qualificationProfile.catalog.expiresAt",
    )
    not_before = max(
        record_not_before,
        catalog_not_before,
        current_ring.not_before,
        qe_key.not_before,
        release_key.not_before,
    )
    horizons = [
        record_expires,
        catalog_expires,
        current_ring.expires_at,
        trust.freshness_expires_at,
        qualification.freshness_expires_at,
        qe_key.not_after,
        release_key.not_after,
    ]
    if next_deny is not None:
        horizons.append(next_deny)
    expires_at = min(horizons)
    require(
        not_before == dependency.not_before and expires_at == dependency.expires_at,
        "QUALIFICATION_VALIDITY_CONTEXT_MISMATCH",
        "qualificationProfile.validity",
        "record/catalog/trust validity does not replay from the dependency",
    )
    require(
        not_before <= qualification.verified_at < expires_at,
        "QUALIFICATION_PROFILE_EXPIRED",
        "qualificationProfile.validity",
        "verified qualification time is outside the exact profile window",
    )
    return not_before, expires_at


def _expected_receipt(
    schemas: ContractSchemas,
    qualification: VerifiedQualificationContext,
    dependency: QualificationProfileDependency,
    record: Mapping[str, Any],
    catalog: Mapping[str, Any],
    projection_digest: str,
    e4_closure: Mapping[str, Any],
    qe_key: Any,
    release_key: Any,
    next_deny: datetime | None,
    expires_at: datetime,
) -> dict[str, Any]:
    trust = qualification.trust
    current_ring = trust._rings[-1]
    schema_bindings = _schema_bindings(schemas)
    algorithm_projection = {
        "algorithmId": "PORTABLE_QUALIFICATION_PROFILE_VERIFIER_V1",
        "algorithmVersion": 1,
        "canonicalProfileId": "CANONICAL-JSON-V1",
        "schemaBindings": schema_bindings,
    }
    receipt: dict[str, Any] = {
        "subjectType": "QUALIFICATION_VERIFICATION_RECEIPT",
        "schemaVersion": 1,
        "canonicalProfileId": "CANONICAL-JSON-V1",
        "verifierAlgorithmId": ("PORTABLE_QUALIFICATION_PROFILE_VERIFIER_V1"),
        "verifierAlgorithmVersion": 1,
        "verifierAlgorithmIdentityDigest": _domain_digest(
            _ALGORITHM_DOMAIN,
            algorithm_projection,
        ),
        "schemaBindings": schema_bindings,
        "projectionDigest": projection_digest,
        "profileId": record["exactQualificationKey"],
        "exactQualificationKey": record["exactQualificationKey"],
        "qualificationRecordDigests": [record["recordDigest"]],
        "qualificationRecord": {
            "qualificationRecordId": record["qualificationRecordId"],
            "recordDigest": record["recordDigest"],
            "exactQualificationKey": record["exactQualificationKey"],
            "platformProfileHash": record["platformProfileHash"],
            "keyRingVersion": record["keyRingVersion"],
            "qualificationSignerKeyId": qe_key.key_id,
            "qualificationSignerPrincipalId": qe_key.principal_id,
            "signerNotBefore": _timestamp_text(qe_key.not_before),
            "signerNotAfter": _timestamp_text(qe_key.not_after),
            "recordNotBefore": record["notBefore"],
            "recordExpiresAt": record["expiresAt"],
        },
        "e4Closure": copy.deepcopy(e4_closure),
        "catalog": {
            "catalogId": catalog["catalogId"],
            "catalogSequence": catalog["catalogSequence"],
            "catalogDigest": catalog["catalogDigest"],
            "qualificationRecordDigests": copy.deepcopy(
                catalog["qualificationRecordDigests"]
            ),
            "keyRingVersion": catalog["keyRingVersion"],
            "productReleaseSignerKeyId": release_key.key_id,
            "productReleaseSignerPrincipalId": release_key.principal_id,
            "signerNotBefore": _timestamp_text(release_key.not_before),
            "signerNotAfter": _timestamp_text(release_key.not_after),
            "catalogNotBefore": catalog["notBefore"],
            "catalogExpiresAt": catalog["expiresAt"],
        },
        "catalogAnchor": {
            "catalogId": qualification.catalog_id,
            "anchorDigest": qualification.catalog_anchor_digest,
            "anchorVersion": qualification.catalog_anchor_version,
            "resourceVersion": (qualification.catalog_anchor_resource_version),
            "authorityId": qualification.catalog_anchor_authority_id,
            "receiptDigest": (qualification.catalog_anchor_receipt_digest),
            "trustRootDigest": trust.root_set_digest,
        },
        "catalogFreshness": {
            "freshnessReceiptDigest": (qualification.freshness_receipt_digest),
            "verifierNonce": qualification.freshness_verifier_nonce,
            "observedAt": _timestamp_text(qualification.freshness_observed_at),
            "expiresAt": _timestamp_text(qualification.freshness_expires_at),
            "trustRootDigest": trust.root_set_digest,
        },
        "trust": {
            "trustContextDigest": trust.context_digest,
            "rootSetId": trust.root_set_id,
            "rootSetDigest": trust.root_set_digest,
            "keyRingId": trust.key_ring_id,
            "keyRingSequence": trust.key_ring_sequence,
            "keyRingDigest": trust.key_ring_digest,
            "verifiedHistoryDigest": trust.verified_history_digest,
            "keyRingNotBefore": _timestamp_text(current_ring.not_before),
            "keyRingExpiresAt": _timestamp_text(current_ring.expires_at),
            "trustAnchorDigest": trust.trust_anchor_digest,
            "trustAnchorVersion": trust.trust_anchor_version,
            "trustAnchorResourceVersion": (trust.trust_anchor_resource_version),
            "trustAnchorAuthorityId": trust.trust_anchor_authority_id,
            "freshnessReceiptDigest": trust.freshness_receipt_digest,
            "freshnessExpiresAt": _timestamp_text(trust.freshness_expires_at),
        },
        "nextApplicableDenyEffectiveAtOrNull": (
            None if next_deny is None else _timestamp_text(next_deny)
        ),
        "verifiedAt": _timestamp_text(qualification.verified_at),
        "expiresAt": _timestamp_text(expires_at),
        "receiptDigest": None,
    }
    receipt["receiptDigest"] = _domain_digest(_RECEIPT_DOMAIN, receipt)
    return receipt


def _call_e4_port(
    verifier: QualificationEvidenceVerifier,
    *,
    record: Mapping[str, Any],
    record_bytes: bytes,
    e4_closure: Mapping[str, Any],
    verified_at: datetime,
) -> None:
    method = getattr(verifier, "verify_e4_closure", None)
    require(
        callable(method),
        "QUALIFICATION_E4_VERIFIER_INVALID",
        "qualificationProfile.evidenceVerifier",
        "expected a QualificationEvidenceVerifier component port",
    )
    try:
        result = method(
            qualification_record_bytes=record_bytes,
            qualification_record_digest=record["recordDigest"],
            exact_qualification_key=record["exactQualificationKey"],
            qualification_subject_manifest_digest=(
                record["qualificationSubjectManifestDigest"]
            ),
            qualification_case_matrix_sha256=(record["qualificationCaseMatrixSha256"]),
            case_ids=tuple(record["caseIds"]),
            e4_evidence_hashes=tuple(record["e4EvidenceHashes"]),
            expected_e4_closure_digest=e4_closure["e4ClosureDigest"],
            verified_at=verified_at,
        )
    except DirectPathVerificationError:
        raise
    except Exception as exc:
        fail(
            "QUALIFICATION_E4_VERIFICATION_FAILED",
            "qualificationProfile.e4Closure",
            f"E4 component port failed: {exc}",
        )
    require(
        result is None,
        "QUALIFICATION_E4_VERIFICATION_FAILED",
        "qualificationProfile.e4Closure",
        "E4 component port must return None only after complete replay",
    )


@dataclass(frozen=True, slots=True, init=False)
class StructuralQualificationProfileContext(FactoryVerified):
    """Factory-only component replay, never product qualification authority.

    ``VerifiedQualificationProfileContext`` is a deprecated compatibility
    alias for this structural-only class.  The legacy name does not imply
    component authority, product authorization, or trusted E4 adapter proof.
    """

    qualification: VerifiedQualificationContext
    dependency: QualificationProfileDependency
    qualification_record: Mapping[str, Any]
    supported_catalog: Mapping[str, Any]
    projection: Mapping[str, Any]
    projection_digest: str
    receipt: Mapping[str, Any]
    receipt_digest: str
    profile: Mapping[str, Any]
    profile_id: str
    profile_hash: str
    profile_semantic_digest: str
    exact_qualification_key: str
    qualification_record_digests: tuple[str, ...]
    qualification_case_matrix_hash: str
    guest_abi_class: str
    support_status: str
    verified_at: datetime
    expires_at: datetime
    verification_disposition: str
    authority_boundary: str
    e4_closure_structurally_valid: bool
    component_authority: bool
    product_authorized: bool
    authorization_blockers: tuple[str, ...]
    context_digest: str

    def __post_init__(self) -> None:
        require(
            type(self) is StructuralQualificationProfileContext,
            "QUALIFICATION_PROFILE_AUTHORITY_INVALID",
            "qualificationProfile.type",
            "subclassed qualification-profile values are not accepted",
        )
        require(
            self.verification_disposition
            == QUALIFICATION_VERIFICATION_DISPOSITION,
            "QUALIFICATION_PROFILE_AUTHORITY_INVALID",
            "qualificationProfile.verificationDisposition",
            "caller-port replay can produce STRUCTURALLY_VALID only",
        )
        require(
            self.authority_boundary == QUALIFICATION_AUTHORITY_BOUNDARY,
            "QUALIFICATION_PROFILE_AUTHORITY_INVALID",
            "qualificationProfile.authorityBoundary",
            "caller-port replay is confined to COMPONENT_ONLY",
        )
        require(
            self.e4_closure_structurally_valid is True,
            "QUALIFICATION_PROFILE_AUTHORITY_INVALID",
            "qualificationProfile.e4ClosureStructurallyValid",
            "the structural factory requires successful closure replay",
        )
        require(
            self.component_authority is False
            and self.product_authorized is False,
            "QUALIFICATION_PROFILE_AUTHORITY_INVALID",
            "qualificationProfile.productAuthorized",
            "the portable factory cannot mint component or product authority",
        )
        require(
            self.authorization_blockers
            == _QUALIFICATION_AUTHORIZATION_BLOCKERS,
            "QUALIFICATION_PROFILE_AUTHORITY_INVALID",
            "qualificationProfile.authorizationBlockers",
            "TRUSTED_E4_ADAPTER_REQUIRED is permanent in the portable result",
        )
        expected_digest = sha256_digest(
            canonical_json_bytes(
                {
                    **self.to_subject(),
                    "contextDigest": None,
                }
            )
        )
        require(
            self.context_digest == expected_digest,
            "QUALIFICATION_PROFILE_CONTEXT_DIGEST_INVALID",
            "qualificationProfile.contextDigest",
            "context digest does not bind the structural authority boundary",
        )

    @classmethod
    def _construct(
        cls,
        **_values: Any,
    ) -> "StructuralQualificationProfileContext":
        raise TypeError(
            "StructuralQualificationProfileContext is constructed only by "
            "verify_qualification_profile"
        )

    @classmethod
    def _construct_structural(
        cls,
        factory_token: object,
        **values: Any,
    ) -> "StructuralQualificationProfileContext":
        if factory_token is not _QUALIFICATION_PROFILE_FACTORY_TOKEN:
            raise TypeError("invalid qualification-profile factory token")
        return FactoryVerified._construct.__func__(cls, **values)

    def to_subject(self) -> dict[str, object]:
        """Return the exact context-digest projection."""

        return {
            "subjectType": "STRUCTURAL_QUALIFICATION_PROFILE_CONTEXT",
            "schemaVersion": 1,
            "qualificationContextDigest": self.qualification.context_digest,
            "dependencyDigest": self.dependency.dependency_digest,
            "qualificationRecordDigest": (self.dependency.qualification_record_digest),
            "catalogDigest": self.qualification.catalog_digest,
            "projectionDigest": self.projection_digest,
            "receiptDigest": self.receipt_digest,
            "profileHash": self.profile_hash,
            "profileSemanticDigest": self.profile_semantic_digest,
            "verifiedAt": _timestamp_text(self.verified_at),
            "expiresAt": _timestamp_text(self.expires_at),
            "verificationDisposition": self.verification_disposition,
            "authorityBoundary": self.authority_boundary,
            "e4ClosureStructurallyValid": self.e4_closure_structurally_valid,
            "componentAuthority": self.component_authority,
            "productAuthorized": self.product_authorized,
            "authorizationBlockers": list(self.authorization_blockers),
            "contextDigest": self.context_digest,
        }


def verify_qualification_profile(
    schemas: ContractSchemas,
    qualification: VerifiedQualificationContext,
    *,
    qualification_record: JsonDocument,
    supported_catalog: JsonDocument,
    evidence_verifier: QualificationEvidenceVerifier,
    receipt_document: JsonDocument,
    profile_document: JsonDocument,
) -> StructuralQualificationProfileContext:
    """Replay one complete qualification profile chain without side effects.

    The ``evidence_verifier`` is a caller-injected component port.  Supplying
    an object or test fake that returns success creates only the explicit
    STRUCTURALLY_VALID/COMPONENT_ONLY result below; it does not create E4
    evidence, repository currentness, product integration, or release
    authority.  Product code must independently provision and authenticate a
    real resolver/repository adapter outside this package.
    """

    require(
        isinstance(schemas, ContractSchemas),
        "QUALIFICATION_PROFILE_INPUT_INVALID",
        "schemas",
        "expected ContractSchemas",
    )
    require_factory_verified(
        qualification,
        VerifiedQualificationContext,
        code="QUALIFICATION_PROFILE_INPUT_INVALID",
        path="qualification",
        message=("qualification must come from verify_qualification_context"),
    )
    record, record_bytes = _document(
        qualification_record,
        "qualificationProfile.qualificationRecord",
    )
    catalog, catalog_bytes = _document(
        supported_catalog,
        "qualificationProfile.catalog",
    )
    schemas.validate(
        "qualification_record",
        record,
        "qualificationProfile.qualificationRecord",
    )
    schemas.validate(
        "catalog",
        catalog,
        "qualificationProfile.catalog",
    )
    dependency, qe_key, release_key, next_deny = _require_context_bindings(
        qualification, record, catalog
    )
    require(
        sha256_digest(record_bytes) == dependency.qualification_record_canonical_digest,
        "QUALIFICATION_RECORD_CONTEXT_MISMATCH",
        "qualificationProfile.qualificationRecord",
        "record canonical bytes differ from the authenticated verifier input",
    )
    require(
        sha256_digest(catalog_bytes) == qualification.catalog_canonical_digest,
        "QUALIFICATION_CATALOG_CONTEXT_MISMATCH",
        "qualificationProfile.catalog",
        "catalog canonical bytes differ from the authenticated verifier input",
    )
    _, expires_at = _validity_window(
        qualification,
        dependency,
        record,
        catalog,
        qe_key,
        release_key,
        next_deny,
    )

    projection = _profile_projection(record, catalog)
    schemas.validate(
        "qualification_profile_projection",
        projection,
        "qualificationProfile.projection",
    )
    projection_digest = _domain_digest(_PROJECTION_DOMAIN, projection)
    e4_closure = _e4_closure(record)
    expected_receipt = _expected_receipt(
        schemas,
        qualification,
        dependency,
        record,
        catalog,
        projection_digest,
        e4_closure,
        qe_key,
        release_key,
        next_deny,
        expires_at,
    )

    receipt, _ = _document(
        receipt_document,
        "qualificationProfile.receipt",
    )
    schemas.validate(
        "qualification_verification_receipt",
        receipt,
        "qualificationProfile.receipt",
    )
    receipt_verified_at = _timestamp(
        receipt["verifiedAt"],
        "qualificationProfile.receipt.verifiedAt",
    )
    receipt_expires_at = _timestamp(
        receipt["expiresAt"],
        "qualificationProfile.receipt.expiresAt",
    )
    require(
        receipt_verified_at < receipt_expires_at,
        "QUALIFICATION_PROFILE_EXPIRED",
        "qualificationProfile.receipt.expiresAt",
        "receipt expiry must be strictly later than its verifiedAt",
    )
    receipt_projection = copy.deepcopy(receipt)
    receipt_projection["receiptDigest"] = None
    require(
        receipt["receiptDigest"] == _domain_digest(_RECEIPT_DOMAIN, receipt_projection),
        "QUALIFICATION_RECEIPT_HASH_INVALID",
        "qualificationProfile.receipt.receiptDigest",
        "receiptDigest does not match the null-digest projection",
    )
    require(
        canonical_json_bytes(receipt) == canonical_json_bytes(expected_receipt),
        "QUALIFICATION_RECEIPT_BINDING_MISMATCH",
        "qualificationProfile.receipt",
        "receipt does not replay from the exact verified inputs",
    )

    expected_profile = {
        **projection,
        "verificationReceiptHash": receipt["receiptDigest"],
        "profileHash": None,
    }
    expected_profile["profileHash"] = sha256_digest(
        canonical_json_bytes(expected_profile)
    )
    profile, _ = _document(
        profile_document,
        "qualificationProfile.profile",
    )
    schemas.validate(
        "portable_hash_subjects",
        profile,
        "qualificationProfile.profile",
    )
    profile_projection = copy.deepcopy(profile)
    profile_projection["profileHash"] = None
    require(
        profile["profileHash"]
        == sha256_digest(canonical_json_bytes(profile_projection)),
        "QUALIFICATION_PROFILE_HASH_INVALID",
        "qualificationProfile.profile.profileHash",
        "profileHash does not match the null-hash final profile projection",
    )
    require(
        canonical_json_bytes(profile) == canonical_json_bytes(expected_profile),
        "QUALIFICATION_PROFILE_BINDING_MISMATCH",
        "qualificationProfile.profile",
        "profile does not replay from the exact projection and receipt",
    )
    profile_semantic_digest = _profile_semantic_digest(profile)

    _call_e4_port(
        evidence_verifier,
        record=record,
        record_bytes=record_bytes,
        e4_closure=e4_closure,
        verified_at=qualification.verified_at,
    )

    subject = {
        "subjectType": "STRUCTURAL_QUALIFICATION_PROFILE_CONTEXT",
        "schemaVersion": 1,
        "qualificationContextDigest": qualification.context_digest,
        "dependencyDigest": dependency.dependency_digest,
        "qualificationRecordDigest": (dependency.qualification_record_digest),
        "catalogDigest": qualification.catalog_digest,
        "projectionDigest": projection_digest,
        "receiptDigest": receipt["receiptDigest"],
        "profileHash": profile["profileHash"],
        "profileSemanticDigest": profile_semantic_digest,
        "verifiedAt": _timestamp_text(qualification.verified_at),
        "expiresAt": _timestamp_text(expires_at),
        "verificationDisposition": QUALIFICATION_VERIFICATION_DISPOSITION,
        "authorityBoundary": QUALIFICATION_AUTHORITY_BOUNDARY,
        "e4ClosureStructurallyValid": True,
        "componentAuthority": False,
        "productAuthorized": False,
        "authorizationBlockers": list(_QUALIFICATION_AUTHORIZATION_BLOCKERS),
        "contextDigest": None,
    }
    context_digest = sha256_digest(canonical_json_bytes(subject))
    return StructuralQualificationProfileContext._construct_structural(
        _QUALIFICATION_PROFILE_FACTORY_TOKEN,
        qualification=qualification,
        dependency=dependency,
        qualification_record=_freeze(record),
        supported_catalog=_freeze(catalog),
        projection=_freeze(projection),
        projection_digest=projection_digest,
        receipt=_freeze(receipt),
        receipt_digest=receipt["receiptDigest"],
        profile=_freeze(profile),
        profile_id=profile["profileId"],
        profile_hash=profile["profileHash"],
        profile_semantic_digest=profile_semantic_digest,
        exact_qualification_key=record["exactQualificationKey"],
        qualification_record_digests=tuple(profile["qualificationRecordDigests"]),
        qualification_case_matrix_hash=(record["qualificationCaseMatrixSha256"]),
        guest_abi_class=profile["guestAbiClass"],
        support_status=profile["supportStatus"],
        verified_at=qualification.verified_at,
        expires_at=expires_at,
        verification_disposition=QUALIFICATION_VERIFICATION_DISPOSITION,
        authority_boundary=QUALIFICATION_AUTHORITY_BOUNDARY,
        e4_closure_structurally_valid=True,
        component_authority=False,
        product_authorized=False,
        authorization_blockers=_QUALIFICATION_AUTHORIZATION_BLOCKERS,
        context_digest=context_digest,
    )


@dataclass(frozen=True, slots=True, init=False)
class StructuralStaticQualificationBindingContext(FactoryVerified):
    """Factory-only structural binding with a permanent product blocker.

    ``VerifiedStaticQualificationBindingContext`` is a deprecated
    compatibility alias for this structural-only class.  The legacy name
    cannot remove ``TRUSTED_E4_ADAPTER_REQUIRED``.
    """

    admission: VerifiedStaticAdmissionContext
    profile: StructuralQualificationProfileContext
    admission_requirement: AdmissionRequirement
    bound_at: datetime
    verification_disposition: str
    authority_boundary: str
    component_authority: bool
    product_authorized: bool
    authorization_blockers: tuple[str, ...]
    context_digest: str

    def __post_init__(self) -> None:
        require(
            type(self) is StructuralStaticQualificationBindingContext,
            "STATIC_QUALIFICATION_AUTHORITY_INVALID",
            "staticQualification.type",
            "subclassed static-qualification values are not accepted",
        )
        require(
            type(self.profile) is StructuralQualificationProfileContext,
            "STATIC_QUALIFICATION_INPUT_INVALID",
            "profile",
            "subclassed qualification-profile values are not accepted",
        )
        require_factory_verified(
            self.profile,
            StructuralQualificationProfileContext,
            code="STATIC_QUALIFICATION_INPUT_INVALID",
            path="profile",
            message="profile must come from verify_qualification_profile",
        )
        self.profile.__post_init__()
        require(
            self.verification_disposition
            == QUALIFICATION_VERIFICATION_DISPOSITION
            and self.authority_boundary == QUALIFICATION_AUTHORITY_BOUNDARY,
            "STATIC_QUALIFICATION_AUTHORITY_INVALID",
            "staticQualification.authorityBoundary",
            "static qualification binding is STRUCTURALLY_VALID/COMPONENT_ONLY",
        )
        require(
            self.component_authority is False
            and self.product_authorized is False,
            "STATIC_QUALIFICATION_AUTHORITY_INVALID",
            "staticQualification.productAuthorized",
            "structural binding cannot mint component or product authority",
        )
        require(
            self.authorization_blockers
            == _QUALIFICATION_AUTHORIZATION_BLOCKERS
            == self.profile.authorization_blockers,
            "STATIC_QUALIFICATION_AUTHORITY_INVALID",
            "staticQualification.authorizationBlockers",
            "TRUSTED_E4_ADAPTER_REQUIRED must survive static binding",
        )
        expected_digest = sha256_digest(
            canonical_json_bytes(
                {
                    **self.to_subject(),
                    "contextDigest": None,
                }
            )
        )
        require(
            self.context_digest == expected_digest,
            "STATIC_QUALIFICATION_CONTEXT_DIGEST_INVALID",
            "staticQualification.contextDigest",
            "context digest does not bind the structural authority boundary",
        )

    @classmethod
    def _construct(
        cls,
        **_values: Any,
    ) -> "StructuralStaticQualificationBindingContext":
        raise TypeError(
            "StructuralStaticQualificationBindingContext is constructed only "
            "by bind_static_qualification_profile"
        )

    @classmethod
    def _construct_structural(
        cls,
        factory_token: object,
        **values: Any,
    ) -> "StructuralStaticQualificationBindingContext":
        if factory_token is not _STATIC_QUALIFICATION_BINDING_FACTORY_TOKEN:
            raise TypeError("invalid static-qualification factory token")
        return FactoryVerified._construct.__func__(cls, **values)

    def to_subject(self) -> dict[str, object]:
        return {
            "subjectType": ("STRUCTURAL_STATIC_QUALIFICATION_BINDING_CONTEXT"),
            "schemaVersion": 1,
            "staticAdmissionContextDigest": self.admission.context_digest,
            "qualificationProfileContextDigest": (self.profile.context_digest),
            "admissionRequirement": self.admission_requirement.value,
            "boundAt": _timestamp_text(self.bound_at),
            "verificationDisposition": self.verification_disposition,
            "authorityBoundary": self.authority_boundary,
            "componentAuthority": self.component_authority,
            "productAuthorized": self.product_authorized,
            "authorizationBlockers": list(self.authorization_blockers),
            "contextDigest": self.context_digest,
        }


def bind_static_qualification_profile(
    admission: VerifiedStaticAdmissionContext,
    profile: StructuralQualificationProfileContext,
) -> StructuralStaticQualificationBindingContext:
    """Bind a static request's exact profile requirements.

    This is a deterministic component binding only.  Neither a caller-created
    request nor a fake E4 port grants product evidence or repository
    authority.  Product integration must still prove the request, policy,
    catalog/profile and trust pointers current through repository reads and
    every side-effect CAS.
    """

    require_factory_verified(
        admission,
        VerifiedStaticAdmissionContext,
        code="STATIC_QUALIFICATION_INPUT_INVALID",
        path="admission",
        message=("admission must come from bind_static_request_policy"),
    )
    require_factory_verified(
        profile,
        StructuralQualificationProfileContext,
        code="STATIC_QUALIFICATION_INPUT_INVALID",
        path="profile",
        message=("profile must come from verify_qualification_profile"),
    )
    require(
        type(profile) is StructuralQualificationProfileContext,
        "STATIC_QUALIFICATION_INPUT_INVALID",
        "profile",
        "subclassed qualification-profile values are not accepted",
    )
    profile.__post_init__()
    request = admission.request
    policy = admission.policy
    request_binding = request.profile_binding
    expected_binding = {
        "profileId": profile.profile_id,
        "profileHash": profile.profile_hash,
        "verificationReceiptHash": profile.receipt_digest,
        "requiredSupportStatus": request_binding["requiredSupportStatus"],
    }
    require(
        canonical_json_bytes(request_binding) == canonical_json_bytes(expected_binding),
        "REQUEST_QUALIFICATION_PROFILE_BINDING_MISMATCH",
        "request.profileBinding",
        "request profileBinding does not exactly identify the verified profile",
    )
    require(
        request.canonical_request["requiredGuestAbiClass"] == profile.guest_abi_class,
        "REQUEST_GUEST_ABI_MISMATCH",
        "request.requiredGuestAbiClass",
        "request guest ABI does not equal the verified profile",
    )
    try:
        requirement = AdmissionRequirement(request_binding["requiredSupportStatus"])
    except (TypeError, ValueError):
        fail(
            "REQUEST_SUPPORT_REQUIREMENT_INVALID",
            "request.profileBinding.requiredSupportStatus",
            "expected QUALIFIED or SUPPORTED",
        )
    require(
        requirement
        in {
            AdmissionRequirement.QUALIFIED,
            AdmissionRequirement.SUPPORTED,
        },
        "REQUEST_SUPPORT_REQUIREMENT_INVALID",
        "request.profileBinding.requiredSupportStatus",
        "static profile binding cannot request TECHNICAL-only admission",
    )
    if policy.admission_mode == "PRODUCTION":
        require(
            requirement is AdmissionRequirement.SUPPORTED,
            "PRODUCTION_REQUIRES_SUPPORTED_PROFILE",
            "request.profileBinding.requiredSupportStatus",
            "PRODUCTION admission must explicitly require SUPPORTED",
        )
    if requirement is AdmissionRequirement.SUPPORTED:
        require(
            profile.support_status == "SUPPORTED",
            "PROFILE_SUPPORT_STATUS_INSUFFICIENT",
            "qualificationProfile.supportStatus",
            "SUPPORTED admission requires a SUPPORTED profile",
        )
    else:
        require(
            profile.support_status in {"QUALIFIED", "SUPPORTED"},
            "PROFILE_SUPPORT_STATUS_INSUFFICIENT",
            "qualificationProfile.supportStatus",
            "QUALIFIED admission requires QUALIFIED or SUPPORTED",
        )
    trust = profile.qualification.trust
    require(
        profile.qualification.catalog_digest == policy.supported_catalog_digest
        and profile.qualification.catalog_sequence == policy.catalog_sequence
        and trust.key_ring_sequence == policy.trust_key_ring_sequence
        and profile.qualification_case_matrix_hash
        == policy.qualification_case_matrix_hash,
        "POLICY_QUALIFICATION_PROFILE_BINDING_MISMATCH",
        "qualificationProfile",
        "profile catalog, key ring or Case matrix does not match policy",
    )
    bound_at = max(policy.verified_at, profile.verified_at)
    require(
        policy.effective_at <= bound_at < policy.expires_at
        and profile.verified_at <= bound_at < profile.expires_at,
        "STATIC_QUALIFICATION_BINDING_EXPIRED",
        "qualificationProfile.validity",
        "policy/profile validity windows do not overlap at binding time",
    )
    subject = {
        "subjectType": ("STRUCTURAL_STATIC_QUALIFICATION_BINDING_CONTEXT"),
        "schemaVersion": 1,
        "staticAdmissionContextDigest": admission.context_digest,
        "qualificationProfileContextDigest": profile.context_digest,
        "admissionRequirement": requirement.value,
        "boundAt": _timestamp_text(bound_at),
        "verificationDisposition": QUALIFICATION_VERIFICATION_DISPOSITION,
        "authorityBoundary": QUALIFICATION_AUTHORITY_BOUNDARY,
        "componentAuthority": False,
        "productAuthorized": False,
        "authorizationBlockers": list(_QUALIFICATION_AUTHORIZATION_BLOCKERS),
        "contextDigest": None,
    }
    context_digest = sha256_digest(canonical_json_bytes(subject))
    return StructuralStaticQualificationBindingContext._construct_structural(
        _STATIC_QUALIFICATION_BINDING_FACTORY_TOKEN,
        admission=admission,
        profile=profile,
        admission_requirement=requirement,
        bound_at=bound_at,
        verification_disposition=QUALIFICATION_VERIFICATION_DISPOSITION,
        authority_boundary=QUALIFICATION_AUTHORITY_BOUNDARY,
        component_authority=False,
        product_authorized=False,
        authorization_blockers=_QUALIFICATION_AUTHORIZATION_BLOCKERS,
        context_digest=context_digest,
    )


# Deprecated compatibility aliases.  Despite the old names, these are the
# structural-only classes above and can never represent product authority.
VerifiedQualificationProfileContext = StructuralQualificationProfileContext
VerifiedStaticQualificationBindingContext = (
    StructuralStaticQualificationBindingContext
)


__all__ = [
    "QUALIFICATION_AUTHORITY_BOUNDARY",
    "QUALIFICATION_VERIFICATION_DISPOSITION",
    "QualificationEvidenceVerifier",
    "StructuralQualificationProfileContext",
    "StructuralStaticQualificationBindingContext",
    "TRUSTED_E4_ADAPTER_REQUIRED",
    "VerifiedQualificationProfileContext",
    "VerifiedStaticQualificationBindingContext",
    "bind_static_qualification_profile",
    "verify_qualification_profile",
]
