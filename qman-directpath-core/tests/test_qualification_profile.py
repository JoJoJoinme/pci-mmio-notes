from __future__ import annotations

import copy
from dataclasses import fields, replace
from datetime import datetime, timezone
import json
from pathlib import Path
import unittest

from qman_directpath_core.admission import bind_static_request_policy
from qman_directpath_core.canonical import (
    canonical_json_bytes,
    sha256_digest,
)
from qman_directpath_core.capability import AdmissionRequirement
from qman_directpath_core.contracts import ContractSchemas
from qman_directpath_core.errors import (
    DirectPathVerificationError,
)
from qman_directpath_core.policy import verify_capability_policy
from qman_directpath_core.qualification_profile import (
    QUALIFICATION_AUTHORITY_BOUNDARY,
    QUALIFICATION_VERIFICATION_DISPOSITION,
    StructuralQualificationProfileContext,
    StructuralStaticQualificationBindingContext,
    TRUSTED_E4_ADAPTER_REQUIRED,
    VerifiedQualificationProfileContext,
    VerifiedStaticQualificationBindingContext,
    bind_static_qualification_profile,
    verify_qualification_profile,
)
from qman_directpath_core._verified import FactoryVerified
from qman_directpath_core.request import verify_static_request
from qman_directpath_core.trust import (
    verify_qualification_context,
    verify_trust_context,
)
from qman_directpath_core import qualification_profile as profile_module
from tests.test_policy import policy_document
from tests.test_request import _rehash, _static_request
from tests.test_trust import (
    NONCE,
    NOW,
    QualificationFixture,
    TrustFixture,
)


ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "contracts"


class PassingEvidenceVerifier:
    """Component fake; its success is deliberately not product E4 proof."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def verify_e4_closure(self, **values: object) -> None:
        self.calls.append(values)


class FailingEvidenceVerifier:
    """Component fake used to prove that the E4 trust port fails closed."""

    def verify_e4_closure(self, **_values: object) -> None:
        raise RuntimeError("artifact resolver rejected the closure")


class NonConformingEvidenceVerifier:
    """A successful-looking non-None return is never accepted."""

    def verify_e4_closure(self, **_values: object) -> bool:
        return True


def profile_documents_for(
    schemas: ContractSchemas,
    qualification,
    fixture: QualificationFixture,
) -> tuple[dict, dict]:
    dependency, qe_key, release_key, next_deny = (
        profile_module._require_context_bindings(
            qualification,
            fixture.record,
            fixture.catalog,
        )
    )
    _, expires_at = profile_module._validity_window(
        qualification,
        dependency,
        fixture.record,
        fixture.catalog,
        qe_key,
        release_key,
        next_deny,
    )
    projection = profile_module._profile_projection(
        fixture.record,
        fixture.catalog,
    )
    projection_digest = profile_module._domain_digest(
        profile_module._PROJECTION_DOMAIN,
        projection,
    )
    e4_closure = profile_module._e4_closure(fixture.record)
    receipt = profile_module._expected_receipt(
        schemas,
        qualification,
        dependency,
        fixture.record,
        fixture.catalog,
        projection_digest,
        e4_closure,
        qe_key,
        release_key,
        next_deny,
        expires_at,
    )
    profile = {
        **projection,
        "verificationReceiptHash": receipt["receiptDigest"],
        "profileHash": None,
    }
    profile["profileHash"] = sha256_digest(canonical_json_bytes(profile))
    return receipt, profile


class QualificationProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schemas = ContractSchemas(CONTRACTS)
        cls.trust_fixture = TrustFixture()
        cls.fixture = QualificationFixture(cls.trust_fixture)
        cls.trust = verify_trust_context(
            cls.schemas,
            pinned_root_set=cls.trust_fixture.root,
            pinned_root_digest=cls.trust_fixture.root["rootSetDigest"],
            key_ring_documents=[cls.trust_fixture.ring],
            external_trust_anchor=cls.trust_fixture.anchor,
            trust_anchor_freshness=cls.trust_fixture.freshness,
            verifier_nonce=NONCE,
            now=NOW,
        )
        cls.qualification = verify_qualification_context(
            cls.schemas,
            cls.trust,
            catalog_documents=[cls.fixture.catalog],
            qualification_records=[cls.fixture.record],
            external_catalog_anchor=cls.fixture.anchor,
            catalog_anchor_freshness=cls.fixture.freshness,
            verifier_nonce=NONCE,
            now=NOW,
        )
        cls.receipt_document, cls.profile_document = cls._valid_profile_documents()

    @classmethod
    def _valid_profile_documents(cls) -> tuple[dict, dict]:
        return cls._profile_documents_for(
            cls.qualification,
            cls.fixture,
        )

    @classmethod
    def _profile_documents_for(
        cls,
        qualification,
        fixture: QualificationFixture,
    ) -> tuple[dict, dict]:
        return profile_documents_for(
            cls.schemas,
            qualification,
            fixture,
        )

    @classmethod
    def _qualification_for_fixture(
        cls,
        fixture: QualificationFixture,
    ):
        trust = verify_trust_context(
            cls.schemas,
            pinned_root_set=fixture.trust.root,
            pinned_root_digest=fixture.trust.root["rootSetDigest"],
            key_ring_documents=[fixture.trust.ring],
            external_trust_anchor=fixture.trust.anchor,
            trust_anchor_freshness=fixture.trust.freshness,
            verifier_nonce=NONCE,
            now=NOW,
        )
        return verify_qualification_context(
            cls.schemas,
            trust,
            catalog_documents=[fixture.catalog],
            qualification_records=[fixture.record],
            external_catalog_anchor=fixture.anchor,
            catalog_anchor_freshness=fixture.freshness,
            verifier_nonce=NONCE,
            now=NOW,
        )

    def _verify_profile(
        self,
        *,
        evidence_verifier: object | None = None,
        record: dict | None = None,
        catalog: dict | None = None,
        receipt: dict | None = None,
        profile: dict | None = None,
    ) -> VerifiedQualificationProfileContext:
        return verify_qualification_profile(
            self.schemas,
            self.qualification,
            qualification_record=(self.fixture.record if record is None else record),
            supported_catalog=(self.fixture.catalog if catalog is None else catalog),
            evidence_verifier=(
                PassingEvidenceVerifier()
                if evidence_verifier is None
                else evidence_verifier
            ),
            receipt_document=(self.receipt_document if receipt is None else receipt),
            profile_document=(self.profile_document if profile is None else profile),
        )

    @staticmethod
    def _rehash_receipt(receipt: dict) -> None:
        receipt["receiptDigest"] = None
        receipt["receiptDigest"] = sha256_digest(
            profile_module._RECEIPT_DOMAIN + canonical_json_bytes(receipt)
        )

    @staticmethod
    def _rehash_profile(profile: dict) -> None:
        profile["profileHash"] = None
        profile["profileHash"] = sha256_digest(canonical_json_bytes(profile))

    def _admission(
        self,
        profile: VerifiedQualificationProfileContext,
        *,
        required_support_status: str = "SUPPORTED",
        required_guest_abi_class: str | None = None,
        profile_hash: str | None = None,
        receipt_hash: str | None = None,
        policy_verified_at: datetime = NOW,
    ):
        policy = policy_document()
        policy.update(
            {
                "admissionMode": "PRODUCTION",
                "supportedCatalogDigest": (profile.qualification.catalog_digest),
                "catalogSequence": (profile.qualification.catalog_sequence),
                "trustKeyRingSequence": (profile.qualification.trust.key_ring_sequence),
                "qualificationCaseMatrixHash": (profile.qualification_case_matrix_hash),
                "effectiveAt": "2026-07-24T01:00:00.000000Z",
                "expiresAt": "2026-07-24T03:00:00.000000Z",
                "policyHash": None,
            }
        )
        policy["policyHash"] = sha256_digest(canonical_json_bytes(policy))

        request = _static_request()
        canonical = request["canonicalRequest"]
        canonical["profileBinding"] = {
            "profileId": profile.profile_id,
            "profileHash": (
                profile.profile_hash if profile_hash is None else profile_hash
            ),
            "verificationReceiptHash": (
                profile.receipt_digest if receipt_hash is None else receipt_hash
            ),
            "requiredSupportStatus": required_support_status,
        }
        guest_abi = (
            profile.guest_abi_class
            if required_guest_abi_class is None
            else required_guest_abi_class
        )
        canonical["requiredGuestAbiClass"] = guest_abi
        request["requiredGuestAbiClass"] = guest_abi
        canonical["policyBinding"] = {
            "policyId": policy["policyId"],
            "policyVersion": policy["policyVersion"],
            "policyHash": policy["policyHash"],
            "admissionMode": policy["admissionMode"],
            "supportedCatalogDigest": policy["supportedCatalogDigest"],
            "catalogSequence": policy["catalogSequence"],
            "trustKeyRingSequence": policy["trustKeyRingSequence"],
            "qualificationCaseMatrixHash": policy["qualificationCaseMatrixHash"],
        }
        _rehash(request)
        verified_request = verify_static_request(
            self.schemas,
            request,
        )
        verified_policy = verify_capability_policy(
            self.schemas,
            policy,
            verified_at=policy_verified_at,
        )
        return bind_static_request_policy(
            verified_request,
            verified_policy,
        )

    def test_replays_projection_receipt_profile_and_e4_port(self) -> None:
        port = PassingEvidenceVerifier()
        verified = self._verify_profile(evidence_verifier=port)

        self.assertIs(type(verified), StructuralQualificationProfileContext)
        self.assertIs(
            VerifiedQualificationProfileContext,
            StructuralQualificationProfileContext,
        )
        self.assertEqual(
            QUALIFICATION_VERIFICATION_DISPOSITION,
            verified.verification_disposition,
        )
        self.assertEqual(
            QUALIFICATION_AUTHORITY_BOUNDARY,
            verified.authority_boundary,
        )
        self.assertTrue(verified.e4_closure_structurally_valid)
        self.assertFalse(verified.component_authority)
        self.assertFalse(verified.product_authorized)
        self.assertEqual(
            (TRUSTED_E4_ADAPTER_REQUIRED,),
            verified.authorization_blockers,
        )
        self.assertEqual(
            {
                "verificationDisposition": "STRUCTURALLY_VALID",
                "authorityBoundary": "COMPONENT_ONLY",
                "e4ClosureStructurallyValid": True,
                "componentAuthority": False,
                "productAuthorized": False,
                "authorizationBlockers": [
                    "TRUSTED_E4_ADAPTER_REQUIRED",
                ],
            },
            {
                key: verified.to_subject()[key]
                for key in (
                    "verificationDisposition",
                    "authorityBoundary",
                    "e4ClosureStructurallyValid",
                    "componentAuthority",
                    "productAuthorized",
                    "authorizationBlockers",
                )
            },
        )
        runtime = self.fixture.record["kernelQemuFirmwareBackend"]
        expected_machine_digest = sha256_digest(
            b"QMAN-DIRECTPATH/QUALIFICATION-PROFILE-MACHINE/V1\x00"
            + canonical_json_bytes(
                {
                    "machineType": runtime["machineType"],
                    "machineVersion": runtime["machineVersion"],
                }
            )
        )
        self.assertEqual(
            expected_machine_digest,
            verified.projection["machineDigest"],
        )
        self.assertEqual(
            self.fixture.record["exactQualificationKey"],
            verified.profile_id,
        )
        self.assertEqual("SUPPORTED", verified.support_status)
        self.assertEqual(
            self.receipt_document["receiptDigest"],
            verified.receipt_digest,
        )
        semantic_subject = profile_module._profile_semantic_projection(verified.profile)
        self.assertEqual(
            sha256_digest(
                profile_module._PROFILE_SEMANTICS_DOMAIN
                + canonical_json_bytes(semantic_subject)
            ),
            verified.profile_semantic_digest,
        )
        self.assertEqual(1, len(port.calls))
        self.assertEqual(
            verified.receipt["e4Closure"]["e4ClosureDigest"],
            port.calls[0]["expected_e4_closure_digest"],
        )
        for binding in verified.receipt["schemaBindings"]:
            file_ref = binding["schemaRef"].partition("#")[0]
            self.assertEqual(
                self.schemas.digest_for_ref(
                    file_ref,
                    path="test.schemaBinding",
                ),
                binding["schemaSha256"],
            )
        self.assertEqual(
            verified.context_digest,
            sha256_digest(
                canonical_json_bytes(
                    {
                        **verified.to_subject(),
                        "contextDigest": None,
                    }
                )
            ),
        )
        with self.assertRaises(TypeError):
            VerifiedQualificationProfileContext()
        with self.assertRaises(TypeError):
            replace(verified)

    def test_caller_port_never_mints_product_authority(self) -> None:
        structural = self._verify_profile(
            evidence_verifier=PassingEvidenceVerifier(),
        )
        self.assertFalse(structural.component_authority)
        self.assertFalse(structural.product_authorized)
        self.assertIn(
            TRUSTED_E4_ADAPTER_REQUIRED,
            structural.authorization_blockers,
        )

        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_qualification_profile(
                self.schemas,
                self.qualification,
                qualification_record=self.fixture.record,
                supported_catalog=self.fixture.catalog,
                evidence_verifier=None,  # type: ignore[arg-type]
                receipt_document=self.receipt_document,
                profile_document=self.profile_document,
            )
        self.assertEqual(
            "QUALIFICATION_E4_VERIFIER_INVALID",
            raised.exception.code,
        )

        with self.assertRaises(TypeError):
            StructuralQualificationProfileContext._construct(
                product_authorized=True,
            )
        with self.assertRaises(TypeError):
            StructuralQualificationProfileContext._construct_structural(
                object(),
                product_authorized=True,
            )

        forged_values = {
            field.name: getattr(structural, field.name)
            for field in fields(structural)
        }
        forged_values["product_authorized"] = True
        forged_values["component_authority"] = True
        forged_values["authorization_blockers"] = ()
        with self.assertRaises(DirectPathVerificationError) as forged:
            FactoryVerified._construct.__func__(
                StructuralQualificationProfileContext,
                **forged_values,
            )
        self.assertEqual(
            "QUALIFICATION_PROFILE_AUTHORITY_INVALID",
            forged.exception.code,
        )
        with self.assertRaises(TypeError):
            replace(structural, product_authorized=True)

        mutated = self._verify_profile(
            evidence_verifier=PassingEvidenceVerifier(),
        )
        object.__setattr__(mutated, "product_authorized", True)
        with self.assertRaises(DirectPathVerificationError) as mutated_error:
            bind_static_qualification_profile(
                self._admission(mutated),
                mutated,
            )
        self.assertEqual(
            "QUALIFICATION_PROFILE_AUTHORITY_INVALID",
            mutated_error.exception.code,
        )

    def test_profile_semantic_projection_is_closed_and_machine_declared(
        self,
    ) -> None:
        verified = self._verify_profile()
        schema = json.loads(
            (
                CONTRACTS / "directpath-qualification-profile-projection.schema.json"
            ).read_text(encoding="utf-8")
        )
        rule = schema["x-qmanProfileSemanticProjection"]
        self.assertEqual(
            "QMAN-DIRECTPATH/QUALIFICATION-PROFILE-SEMANTICS/V1",
            rule["hashDomain"],
        )
        self.assertEqual(
            profile_module._PROFILE_SEMANTIC_FIELDS,
            tuple(rule["includedProfileFields"]),
        )
        self.assertEqual(
            profile_module._PROFILE_SEMANTIC_EXCLUDED_FIELDS,
            tuple(rule["excludedCurrentnessFields"]),
        )

        baseline = verified.profile_semantic_digest
        for field_name in profile_module._PROFILE_SEMANTIC_FIELDS:
            with self.subTest(included=field_name):
                changed = copy.deepcopy(self.profile_document)
                changed[field_name] = f"changed-{field_name}"
                self.assertNotEqual(
                    baseline,
                    profile_module._profile_semantic_digest(changed),
                )
        changed_currentness = copy.deepcopy(self.profile_document)
        changed_currentness.update(
            {
                "qualificationRecordDigests": ["sha256:" + "1" * 64],
                "supportedCatalogDigest": "sha256:" + "2" * 64,
                "catalogSequence": (changed_currentness["catalogSequence"] + 1),
                "verificationReceiptHash": "sha256:" + "3" * 64,
                "profileHash": "sha256:" + "4" * 64,
            }
        )
        self.assertEqual(
            baseline,
            profile_module._profile_semantic_digest(changed_currentness),
        )

    def test_projection_receipt_profile_and_record_tamper_fail(self) -> None:
        changed_projection_profile = copy.deepcopy(self.profile_document)
        changed_projection_profile["machineDigest"] = "sha256:" + "9" * 64
        self._rehash_profile(changed_projection_profile)

        changed_receipt = copy.deepcopy(self.receipt_document)
        changed_receipt["projectionDigest"] = "sha256:" + "8" * 64
        self._rehash_receipt(changed_receipt)
        profile_for_changed_receipt = copy.deepcopy(self.profile_document)
        profile_for_changed_receipt["verificationReceiptHash"] = changed_receipt[
            "receiptDigest"
        ]
        self._rehash_profile(profile_for_changed_receipt)

        changed_profile = copy.deepcopy(self.profile_document)
        changed_profile["guestAbiClass"] = "forged-abi"
        self._rehash_profile(changed_profile)

        changed_record = copy.deepcopy(self.fixture.record)
        changed_record["e4EvidenceHashes"][0] = "sha256:" + "5" * 64
        changed_record["e4EvidenceHashes"].sort()
        changed_catalog = copy.deepcopy(self.fixture.catalog)
        changed_catalog["issuedAt"] = "2026-07-24T01:46:00.000001Z"

        attempts = (
            {
                "profile": changed_projection_profile,
                "expected": "QUALIFICATION_PROFILE_BINDING_MISMATCH",
            },
            {
                "receipt": changed_receipt,
                "profile": profile_for_changed_receipt,
                "expected": "QUALIFICATION_RECEIPT_BINDING_MISMATCH",
            },
            {
                "profile": changed_profile,
                "expected": "QUALIFICATION_PROFILE_BINDING_MISMATCH",
            },
            {
                "record": changed_record,
                "expected": "QUALIFICATION_RECORD_CONTEXT_MISMATCH",
            },
            {
                "catalog": changed_catalog,
                "expected": "QUALIFICATION_CATALOG_CONTEXT_MISMATCH",
            },
        )
        for attempt in attempts:
            expected = attempt.pop("expected")
            with self.subTest(expected=expected):
                with self.assertRaises(DirectPathVerificationError) as raised:
                    self._verify_profile(**attempt)
                self.assertEqual(expected, raised.exception.code)

    def test_expired_receipt_and_e4_port_failure_fail_closed(self) -> None:
        expired_receipt = copy.deepcopy(self.receipt_document)
        expired_receipt["expiresAt"] = expired_receipt["verifiedAt"]
        self._rehash_receipt(expired_receipt)
        expired_profile = copy.deepcopy(self.profile_document)
        expired_profile["verificationReceiptHash"] = expired_receipt["receiptDigest"]
        self._rehash_profile(expired_profile)
        with self.assertRaises(DirectPathVerificationError) as raised:
            self._verify_profile(
                receipt=expired_receipt,
                profile=expired_profile,
            )
        self.assertEqual(
            "QUALIFICATION_PROFILE_EXPIRED",
            raised.exception.code,
        )

        for verifier in (
            FailingEvidenceVerifier(),
            NonConformingEvidenceVerifier(),
        ):
            with self.subTest(verifier=type(verifier).__name__):
                with self.assertRaises(DirectPathVerificationError) as raised:
                    self._verify_profile(
                        evidence_verifier=verifier,
                    )
                self.assertEqual(
                    "QUALIFICATION_E4_VERIFICATION_FAILED",
                    raised.exception.code,
                )

    def test_future_deny_is_bound_into_receipt_and_expiry(self) -> None:
        fixture = QualificationFixture(TrustFixture())
        deny_at = "2026-07-24T02:01:00.000000Z"
        fixture.catalog["denyAndRevocationEntries"] = [
            {
                "entryId": "future-deny-profile-receipt-test",
                "selectorKind": "QUALIFICATION_RECORD",
                "selectorDigest": fixture.record["recordDigest"],
                "reasonCode": "QUALIFICATION_REVOKED_TEST",
                "severity": "NORMAL",
                "revocationBehavior": "DENY_NEW_AND_NEXT_POWER_ON",
                "effectiveAt": deny_at,
                "evidenceHash": sha256_digest(b"future-deny-evidence"),
            }
        ]
        fixture.resign_catalog(fixture.catalog)
        fixture.anchor = fixture._catalog_anchor()
        fixture.freshness = fixture._catalog_freshness()
        qualification = self._qualification_for_fixture(fixture)
        receipt, profile = self._profile_documents_for(
            qualification,
            fixture,
        )

        verified = verify_qualification_profile(
            self.schemas,
            qualification,
            qualification_record=fixture.record,
            supported_catalog=fixture.catalog,
            evidence_verifier=PassingEvidenceVerifier(),
            receipt_document=receipt,
            profile_document=profile,
        )

        self.assertEqual(
            deny_at,
            verified.receipt["nextApplicableDenyEffectiveAtOrNull"],
        )
        self.assertEqual(deny_at, verified.receipt["expiresAt"])
        self.assertEqual(
            datetime(2026, 7, 24, 2, 1, tzinfo=timezone.utc),
            verified.expires_at,
        )

    def test_controlled_stop_catalog_maps_to_critical_profile(self) -> None:
        fixture = QualificationFixture(TrustFixture())
        controlled_stop = "DENY_NEW_AND_REQUIRE_CONTROLLED_STOP"
        fixture.catalog["revocationBehavior"] = controlled_stop
        fixture.resign_catalog(fixture.catalog)
        fixture.anchor = fixture._catalog_anchor()
        fixture.freshness = fixture._catalog_freshness()
        qualification = self._qualification_for_fixture(fixture)
        receipt, profile = self._profile_documents_for(
            qualification,
            fixture,
        )

        verified = verify_qualification_profile(
            self.schemas,
            qualification,
            qualification_record=fixture.record,
            supported_catalog=fixture.catalog,
            evidence_verifier=PassingEvidenceVerifier(),
            receipt_document=receipt,
            profile_document=profile,
        )

        self.assertEqual(
            "CRITICAL",
            verified.profile["revocationSeverity"],
        )
        self.assertEqual(
            controlled_stop,
            verified.profile["revocationBehavior"],
        )
        self.assertEqual(
            verified.projection_digest,
            verified.receipt["projectionDigest"],
        )
        self.assertEqual(
            fixture.catalog["catalogDigest"],
            verified.receipt["catalog"]["catalogDigest"],
        )
        self.assertEqual(
            verified.receipt_digest,
            verified.profile["verificationReceiptHash"],
        )
        profile_projection = copy.deepcopy(profile)
        profile_projection["profileHash"] = None
        self.assertEqual(
            sha256_digest(canonical_json_bytes(profile_projection)),
            verified.profile_hash,
        )

    def test_static_request_profile_and_support_binding_is_exact(self) -> None:
        profile = self._verify_profile()
        admission = self._admission(profile)
        binding = bind_static_qualification_profile(
            admission,
            profile,
        )

        self.assertEqual(
            AdmissionRequirement.SUPPORTED,
            binding.admission_requirement,
        )
        self.assertIs(
            type(binding),
            StructuralStaticQualificationBindingContext,
        )
        self.assertIs(
            VerifiedStaticQualificationBindingContext,
            StructuralStaticQualificationBindingContext,
        )
        self.assertEqual(
            QUALIFICATION_VERIFICATION_DISPOSITION,
            binding.verification_disposition,
        )
        self.assertEqual(
            QUALIFICATION_AUTHORITY_BOUNDARY,
            binding.authority_boundary,
        )
        self.assertFalse(binding.component_authority)
        self.assertFalse(binding.product_authorized)
        self.assertEqual(
            (TRUSTED_E4_ADAPTER_REQUIRED,),
            binding.authorization_blockers,
        )
        self.assertEqual(
            [
                TRUSTED_E4_ADAPTER_REQUIRED,
            ],
            binding.to_subject()["authorizationBlockers"],
        )
        self.assertEqual(
            binding.context_digest,
            sha256_digest(
                canonical_json_bytes(
                    {
                        **binding.to_subject(),
                        "contextDigest": None,
                    }
                )
            ),
        )
        with self.assertRaises(TypeError):
            VerifiedStaticQualificationBindingContext()
        with self.assertRaises(TypeError):
            replace(binding)
        with self.assertRaises(TypeError):
            replace(binding, product_authorized=True)

        forged_values = {
            field.name: getattr(binding, field.name)
            for field in fields(binding)
        }
        forged_values["product_authorized"] = True
        forged_values["authorization_blockers"] = ()
        with self.assertRaises(DirectPathVerificationError) as forged:
            FactoryVerified._construct.__func__(
                StructuralStaticQualificationBindingContext,
                **forged_values,
            )
        self.assertEqual(
            "STATIC_QUALIFICATION_AUTHORITY_INVALID",
            forged.exception.code,
        )

        attempts = (
            (
                self._admission(
                    profile,
                    profile_hash="sha256:" + "7" * 64,
                ),
                "REQUEST_QUALIFICATION_PROFILE_BINDING_MISMATCH",
            ),
            (
                self._admission(
                    profile,
                    receipt_hash="sha256:" + "6" * 64,
                ),
                "REQUEST_QUALIFICATION_PROFILE_BINDING_MISMATCH",
            ),
            (
                self._admission(
                    profile,
                    required_guest_abi_class="forged-abi",
                ),
                "REQUEST_GUEST_ABI_MISMATCH",
            ),
            (
                self._admission(
                    profile,
                    required_support_status="QUALIFIED",
                ),
                "PRODUCTION_REQUIRES_SUPPORTED_PROFILE",
            ),
        )
        for changed_admission, expected in attempts:
            with self.subTest(expected=expected):
                with self.assertRaises(DirectPathVerificationError) as raised:
                    bind_static_qualification_profile(
                        changed_admission,
                        profile,
                    )
                self.assertEqual(expected, raised.exception.code)

    def test_static_binding_rejects_an_expired_profile_context(self) -> None:
        profile = self._verify_profile()
        after_profile_expiry = datetime(
            2026,
            7,
            24,
            2,
            3,
            tzinfo=timezone.utc,
        )
        admission = self._admission(
            profile,
            policy_verified_at=after_profile_expiry,
        )
        with self.assertRaises(DirectPathVerificationError) as raised:
            bind_static_qualification_profile(admission, profile)
        self.assertEqual(
            "STATIC_QUALIFICATION_BINDING_EXPIRED",
            raised.exception.code,
        )


if __name__ == "__main__":
    unittest.main()
