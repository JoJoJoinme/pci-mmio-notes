from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import unittest

import qman_directpath_core
from qman_directpath_core.authority import (
    AvailabilityMemberVersion,
    AvailabilityReadSet,
    CapabilityAuthorityDisposition,
    CurrentAuthorityVector,
    RequestReadSet,
    ScopedCapabilityDependencies,
    _bind_authorization,
    assert_current,
    semantic_cache_reusable,
)
from qman_directpath_core.canonical import (
    canonical_json_bytes,
    sha256_digest,
)
from qman_directpath_core.errors import DirectPathVerificationError


CHECKED_AT = datetime(2026, 7, 24, 0, 0, tzinfo=timezone.utc)
VALID_UNTIL = CHECKED_AT + timedelta(minutes=5)
EVIDENCE_VALID_UNTIL = CHECKED_AT + timedelta(minutes=10)


def digest(character: str) -> str:
    return "sha256:" + (character * 64)


def authority_disposition() -> CapabilityAuthorityDisposition:
    return CapabilityAuthorityDisposition(
        static_capability_context_digest=digest("1"),
        hardware_premise_digest=digest("2"),
        hardware_premise_authority_boundary=(
            "COMPONENT_VERIFIED_INVENTORY_PREMISE_ONLY"
        ),
        resource_plan_context_digest=digest("3"),
        resource_plan_hash=digest("4"),
        resource_plan_authority_boundary=(
            "COMPONENT_CALLER_SUPPLIED_RESOURCE_PLAN_BYTES_ONLY"
        ),
        qualification_binding_context_digest=digest("5"),
        qualification_authority_boundary="COMPONENT_ONLY",
        host_snapshot_anchor_binding_digest=digest("6"),
        host_snapshot_anchor_authority_boundary=(
            "COMPONENT_EXTERNAL_BYTES_VERIFICATION_ONLY"
        ),
        authorization_blockers=(
            "PRODUCT_HOST_SNAPSHOT_AUTHORITY_ADAPTER_REQUIRED",
            "PRODUCT_INVENTORY_COLLECTOR_PUBLISHER_REQUIRED",
            "PRODUCT_REPOSITORY_LEASE_CAS_REQUIRED",
            "PRODUCT_RESOURCE_PLANNER_REQUIRED",
            "TRUSTED_E4_ADAPTER_REQUIRED",
        ),
    )


def bind_authorization(**kwargs):
    return _bind_authorization(
        authority_disposition=authority_disposition(),
        **kwargs,
    )


def availability_read_set(
    *,
    authority_resource_version: int = 19,
    bundle_digest: str | None = None,
    blocking_claim_digests: tuple[str, ...] = (),
) -> AvailabilityReadSet:
    members = (
        AvailabilityMemberVersion("device-a", 3, 11),
        AvailabilityMemberVersion("device-b", 4, 12),
    )
    unhashed = {
        "subjectType": "AVAILABILITY_READ_SET",
        "schemaVersion": 1,
        "authorityId": "qman-global-repository",
        "authorityResourceVersion": authority_resource_version,
        "bundleDigest": bundle_digest or digest("6"),
        "memberVersions": [member.to_subject() for member in members],
        "blockingClaimDigests": list(blocking_claim_digests),
        "blockingQuarantineRecordDigests": [],
        "readSetDigest": None,
    }
    return AvailabilityReadSet(
        authority_id="qman-global-repository",
        authority_resource_version=authority_resource_version,
        bundle_digest=bundle_digest or digest("6"),
        member_versions=members,
        blocking_claim_digests=blocking_claim_digests,
        blocking_quarantine_record_digests=(),
        read_set_digest=sha256_digest(canonical_json_bytes(unhashed)),
    )


def request_read_set(
    *,
    request_version: int = 1,
    request_resource_version: int = 19,
    request_hash: str | None = None,
    request_entity_digest: str | None = None,
) -> RequestReadSet:
    resolved_request_hash = request_hash or digest("7")
    resolved_entity_digest = request_entity_digest or digest("0")
    unhashed = {
        "subjectType": "REQUEST_READ_SET",
        "schemaVersion": 1,
        "authorityId": "qman-global-repository",
        "vmId": "vm-a",
        "requestVersion": request_version,
        "requestResourceVersion": request_resource_version,
        "requestHash": resolved_request_hash,
        "requestEntityDigest": resolved_entity_digest,
        "readSetDigest": None,
    }
    return RequestReadSet(
        authority_id="qman-global-repository",
        vm_id="vm-a",
        request_version=request_version,
        request_resource_version=request_resource_version,
        request_hash=resolved_request_hash,
        request_entity_digest=resolved_entity_digest,
        read_set_digest=sha256_digest(canonical_json_bytes(unhashed)),
    )


def dependencies() -> ScopedCapabilityDependencies:
    return ScopedCapabilityDependencies(
        publisher_snapshot_digest=digest("1"),
        hardware_snapshot_semantic_digest=digest("0"),
        policy_digest=digest("2"),
        qualification_profile_digest=digest("3"),
        qualification_profile_semantic_digest=digest("f"),
        qualification_record_digests=(digest("4"),),
        qualification_signer_key_ids=("qe-key-v1",),
        inventory_verifier_identity_digest=digest("5"),
        dependency_bundle_digest=digest("6"),
        dependency_bundle_semantic_digest=digest("6"),
        reset_contract_digest=digest("a"),
        closure_request_digest=digest("b"),
        availability_read_set_digest=(availability_read_set().read_set_digest),
        request_read_set_digest=request_read_set().read_set_digest,
        request_digest=digest("7"),
    )


def authority() -> CurrentAuthorityVector:
    return CurrentAuthorityVector(
        host_authority_id="host-a",
        host_authority_resource_version=9,
        publisher_snapshot_digest=digest("1"),
        host_snapshot_anchor_authority_id=(
            "external-host-snapshot-authority"
        ),
        host_snapshot_anchor_version=3,
        host_snapshot_anchor_resource_version=3,
        host_snapshot_anchor_digest=digest("c"),
        host_snapshot_anchor_freshness_receipt_digest=digest("d"),
        host_snapshot_anchor_binding_digest=digest("e"),
        policy_authority_id="qman-policy-authority",
        policy_id="directpath-production-policy",
        policy_version=7,
        policy_digest=digest("2"),
        policy_authority_resource_version=11,
        trust_root_digest=digest("8"),
        key_ring_sequence=4,
        key_ring_digest=digest("9"),
        trust_anchor_version=4,
        trust_anchor_digest=digest("a"),
        catalog_id="catalog-a",
        catalog_sequence=7,
        catalog_digest=digest("b"),
        catalog_anchor_version=7,
        catalog_anchor_digest=digest("c"),
        availability_authority_id="qman-global-repository",
        availability_authority_resource_version=19,
        availability_read_set_digest=(availability_read_set().read_set_digest),
        request_authority_id="qman-global-repository",
        request_read_set_digest=request_read_set().read_set_digest,
        inventory_verification_receipt_digest=digest("d"),
        inventory_verifier_identity_digest=digest("5"),
        evidence_valid_until=EVIDENCE_VALID_UNTIL,
    )


class AuthorityBindingTests(unittest.TestCase):
    def test_raw_decision_rebinding_is_not_a_public_api(self) -> None:
        self.assertFalse(hasattr(qman_directpath_core, "bind_authorization"))
        token = bind_authorization(
            decision_digest=digest("e"),
            dependencies=dependencies(),
            current=authority(),
            availability_read_set=availability_read_set(),
            request_read_set=request_read_set(),
            evaluated_at=CHECKED_AT,
            valid_until=VALID_UNTIL,
        )
        with self.assertRaises(TypeError):
            replace(token, decision_digest=digest("f"))

    def test_repeat_binding_is_byte_stable(self) -> None:
        first = bind_authorization(
            decision_digest=digest("e"),
            dependencies=dependencies(),
            current=authority(),
            availability_read_set=availability_read_set(),
            request_read_set=request_read_set(),
            evaluated_at=CHECKED_AT,
            valid_until=VALID_UNTIL,
        )
        second = bind_authorization(
            decision_digest=digest("e"),
            dependencies=dependencies(),
            current=authority(),
            availability_read_set=availability_read_set(),
            request_read_set=request_read_set(),
            evaluated_at=CHECKED_AT,
            valid_until=VALID_UNTIL,
        )

        self.assertEqual(first, second)
        assert_current(
            first,
            authority(),
            at=CHECKED_AT,
            expected_decision_digest=digest("e"),
            dependencies=dependencies(),
        )

    def test_any_global_currentness_advance_invalidates_old_authorization(self) -> None:
        token = bind_authorization(
            decision_digest=digest("e"),
            dependencies=dependencies(),
            current=authority(),
            availability_read_set=availability_read_set(),
            request_read_set=request_read_set(),
            evaluated_at=CHECKED_AT,
            valid_until=VALID_UNTIL,
        )
        changes = (
            {"host_authority_resource_version": 10},
            {
                "host_snapshot_anchor_authority_id": (
                    "other-host-snapshot-authority"
                )
            },
            {"host_snapshot_anchor_version": 4},
            {"host_snapshot_anchor_resource_version": 4},
            {"host_snapshot_anchor_digest": digest("f")},
            {
                "host_snapshot_anchor_freshness_receipt_digest": (
                    digest("f")
                )
            },
            {"host_snapshot_anchor_binding_digest": digest("f")},
            {"policy_authority_id": "other-policy-authority"},
            {"policy_id": "other-directpath-policy"},
            {"policy_version": 8},
            {"policy_authority_resource_version": 12},
            {"key_ring_sequence": 5, "key_ring_digest": digest("f")},
            {"trust_anchor_version": 5, "trust_anchor_digest": digest("f")},
            {"catalog_sequence": 8, "catalog_digest": digest("f")},
            {
                "catalog_anchor_version": 8,
                "catalog_anchor_digest": digest("f"),
            },
            {"availability_read_set_digest": digest("f")},
            {"request_read_set_digest": digest("f")},
            {"request_authority_id": "other-request-repository"},
            {"inventory_verification_receipt_digest": digest("f")},
            {"inventory_verifier_identity_digest": digest("f")},
        )
        for change in changes:
            with self.subTest(change=change):
                with self.assertRaises(DirectPathVerificationError) as raised:
                    assert_current(
                        token,
                        replace(authority(), **change),
                        at=CHECKED_AT,
                        expected_decision_digest=digest("e"),
                        dependencies=dependencies(),
                    )
                self.assertEqual(raised.exception.code, "STALE_AUTHORITY")

    def test_disjoint_profile_change_can_reuse_semantics_but_not_admission(
        self,
    ) -> None:
        selected = dependencies()
        token = bind_authorization(
            decision_digest=digest("e"),
            dependencies=selected,
            current=authority(),
            availability_read_set=availability_read_set(),
            request_read_set=request_read_set(),
            evaluated_at=CHECKED_AT,
            valid_until=VALID_UNTIL,
        )

        # A different catalog revision changes the global authorization vector,
        # while the selected profile's complete dependency set is unchanged.
        unrelated_catalog_advance = replace(
            authority(),
            catalog_sequence=8,
            catalog_digest=digest("f"),
            catalog_anchor_version=8,
            catalog_anchor_digest=digest("f"),
            inventory_verification_receipt_digest=digest("f"),
        )
        self.assertTrue(semantic_cache_reusable(token, selected))
        with self.assertRaises(DirectPathVerificationError):
            assert_current(
                token,
                unrelated_catalog_advance,
                at=CHECKED_AT,
                expected_decision_digest=digest("e"),
                dependencies=selected,
            )

    def test_referenced_profile_or_signer_change_invalidates_semantic_cache(
        self,
    ) -> None:
        token = bind_authorization(
            decision_digest=digest("e"),
            dependencies=dependencies(),
            current=authority(),
            availability_read_set=availability_read_set(),
            request_read_set=request_read_set(),
            evaluated_at=CHECKED_AT,
            valid_until=VALID_UNTIL,
        )
        changed_profile = replace(
            dependencies(),
            qualification_profile_semantic_digest=digest("e"),
        )
        changed_signer = replace(
            dependencies(),
            qualification_signer_key_ids=("qe-key-v2",),
        )
        changed_reset_contract = replace(
            dependencies(),
            reset_contract_digest=digest("b"),
        )
        changed_closure_request = replace(
            dependencies(),
            closure_request_digest=digest("c"),
        )
        exact_bundle_refresh = replace(
            dependencies(),
            dependency_bundle_digest=digest("b"),
        )

        self.assertFalse(semantic_cache_reusable(token, changed_profile))
        self.assertFalse(semantic_cache_reusable(token, changed_signer))
        self.assertFalse(semantic_cache_reusable(token, changed_reset_contract))
        self.assertFalse(semantic_cache_reusable(token, changed_closure_request))
        self.assertTrue(semantic_cache_reusable(token, exact_bundle_refresh))

        global_profile_refresh = replace(
            dependencies(),
            qualification_profile_digest=digest("e"),
        )
        self.assertTrue(semantic_cache_reusable(token, global_profile_refresh))

    def test_availability_only_change_reuses_semantics_but_stales_token(
        self,
    ) -> None:
        token = bind_authorization(
            decision_digest=digest("e"),
            dependencies=dependencies(),
            current=authority(),
            availability_read_set=availability_read_set(),
            request_read_set=request_read_set(),
            evaluated_at=CHECKED_AT,
            valid_until=VALID_UNTIL,
        )
        busy_read_set = availability_read_set(
            authority_resource_version=20,
            blocking_claim_digests=(digest("b"),),
        )
        busy_dependencies = replace(
            dependencies(),
            availability_read_set_digest=busy_read_set.read_set_digest,
        )
        busy_current = replace(
            authority(),
            availability_authority_resource_version=20,
            availability_read_set_digest=busy_read_set.read_set_digest,
        )

        self.assertTrue(semantic_cache_reusable(token, busy_dependencies))
        with self.assertRaises(DirectPathVerificationError):
            assert_current(
                token,
                busy_current,
                at=CHECKED_AT,
                expected_decision_digest=digest("e"),
                dependencies=dependencies(),
            )
        rebound = bind_authorization(
            decision_digest=digest("e"),
            dependencies=busy_dependencies,
            current=busy_current,
            availability_read_set=busy_read_set,
            request_read_set=request_read_set(),
            evaluated_at=CHECKED_AT,
            valid_until=VALID_UNTIL,
        )
        assert_current(
            rebound,
            busy_current,
            at=CHECKED_AT,
            expected_decision_digest=digest("e"),
            dependencies=busy_dependencies,
        )

    def test_request_row_version_change_reuses_semantics_but_stales_token(
        self,
    ) -> None:
        selected = dependencies()
        token = bind_authorization(
            decision_digest=digest("e"),
            dependencies=selected,
            current=authority(),
            availability_read_set=availability_read_set(),
            request_read_set=request_read_set(),
            evaluated_at=CHECKED_AT,
            valid_until=VALID_UNTIL,
        )
        advanced_read_set = request_read_set(
            request_resource_version=20,
        )
        advanced_dependencies = replace(
            selected,
            request_read_set_digest=advanced_read_set.read_set_digest,
        )
        advanced_current = replace(
            authority(),
            request_read_set_digest=advanced_read_set.read_set_digest,
        )

        self.assertTrue(semantic_cache_reusable(token, advanced_dependencies))
        with self.assertRaises(DirectPathVerificationError):
            assert_current(
                token,
                advanced_current,
                at=CHECKED_AT,
                expected_decision_digest=digest("e"),
                dependencies=selected,
            )
        rebound = bind_authorization(
            decision_digest=digest("e"),
            dependencies=advanced_dependencies,
            current=advanced_current,
            availability_read_set=availability_read_set(),
            request_read_set=advanced_read_set,
            evaluated_at=CHECKED_AT,
            valid_until=VALID_UNTIL,
        )
        assert_current(
            rebound,
            advanced_current,
            at=CHECKED_AT,
            expected_decision_digest=digest("e"),
            dependencies=advanced_dependencies,
        )

    def test_authorization_expires_even_when_digests_are_unchanged(
        self,
    ) -> None:
        token = bind_authorization(
            decision_digest=digest("e"),
            dependencies=dependencies(),
            current=authority(),
            availability_read_set=availability_read_set(),
            request_read_set=request_read_set(),
            evaluated_at=CHECKED_AT,
            valid_until=VALID_UNTIL,
        )

        assert_current(
            token,
            authority(),
            at=VALID_UNTIL - timedelta(microseconds=1),
            expected_decision_digest=digest("e"),
            dependencies=dependencies(),
        )
        for stale_time in (
            CHECKED_AT - timedelta(microseconds=1),
            VALID_UNTIL,
            VALID_UNTIL + timedelta(seconds=1),
        ):
            with self.subTest(stale_time=stale_time):
                with self.assertRaises(DirectPathVerificationError) as raised:
                    assert_current(
                        token,
                        authority(),
                        at=stale_time,
                        expected_decision_digest=digest("e"),
                        dependencies=dependencies(),
                    )
                self.assertEqual(raised.exception.code, "STALE_AUTHORITY")

        with self.assertRaises(DirectPathVerificationError) as raised:
            bind_authorization(
                decision_digest=digest("e"),
                dependencies=dependencies(),
                current=authority(),
                availability_read_set=availability_read_set(),
                request_read_set=request_read_set(),
                evaluated_at=CHECKED_AT,
                valid_until=EVIDENCE_VALID_UNTIL + timedelta(microseconds=1),
            )
        self.assertEqual(raised.exception.code, "STALE_AUTHORITY")

    def test_authorization_cannot_be_mixed_with_another_decision_or_reset(
        self,
    ) -> None:
        token = bind_authorization(
            decision_digest=digest("e"),
            dependencies=dependencies(),
            current=authority(),
            availability_read_set=availability_read_set(),
            request_read_set=request_read_set(),
            evaluated_at=CHECKED_AT,
            valid_until=VALID_UNTIL,
        )
        for expected_decision, selected_dependencies in (
            (digest("f"), dependencies()),
            (
                digest("e"),
                replace(
                    dependencies(),
                    reset_contract_digest=digest("b"),
                ),
            ),
        ):
            with self.subTest(
                expected_decision=expected_decision,
                selected_dependencies=selected_dependencies,
            ):
                with self.assertRaises(DirectPathVerificationError) as raised:
                    assert_current(
                        token,
                        authority(),
                        at=CHECKED_AT,
                        expected_decision_digest=expected_decision,
                        dependencies=selected_dependencies,
                    )
                self.assertEqual(raised.exception.code, "STALE_AUTHORITY")

    def test_availability_predicate_must_cover_selected_bundle(self) -> None:
        wrong_bundle = availability_read_set(
            bundle_digest=digest("f"),
        )
        with self.assertRaises(DirectPathVerificationError) as raised:
            bind_authorization(
                decision_digest=digest("e"),
                dependencies=replace(
                    dependencies(),
                    availability_read_set_digest=(wrong_bundle.read_set_digest),
                ),
                current=authority(),
                availability_read_set=wrong_bundle,
                request_read_set=request_read_set(),
                evaluated_at=CHECKED_AT,
                valid_until=VALID_UNTIL,
            )
        self.assertEqual(raised.exception.code, "STALE_AUTHORITY")

    def test_availability_read_set_is_closed_hashed_and_ordered(self) -> None:
        members = (
            AvailabilityMemberVersion("device-a", 3, 11),
            AvailabilityMemberVersion("device-b", 4, 12),
        )
        unhashed = {
            "subjectType": "AVAILABILITY_READ_SET",
            "schemaVersion": 1,
            "authorityId": "qman-global-repository",
            "authorityResourceVersion": 19,
            "bundleDigest": digest("6"),
            "memberVersions": [member.to_subject() for member in members],
            "blockingClaimDigests": [],
            "blockingQuarantineRecordDigests": [],
            "readSetDigest": None,
        }
        read_set = AvailabilityReadSet(
            authority_id="qman-global-repository",
            authority_resource_version=19,
            bundle_digest=digest("6"),
            member_versions=members,
            blocking_claim_digests=(),
            blocking_quarantine_record_digests=(),
            read_set_digest=sha256_digest(canonical_json_bytes(unhashed)),
        )

        self.assertEqual(
            read_set.read_set_digest,
            read_set.to_subject()["readSetDigest"],
        )
        for changed in (
            {"read_set_digest": digest("f")},
            {"member_versions": tuple(reversed(members))},
            {"member_versions": (members[0], members[0])},
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(DirectPathVerificationError):
                    replace(read_set, **changed)

    def test_request_read_set_is_closed_hashed_and_versioned(self) -> None:
        read_set = request_read_set()

        self.assertEqual(
            read_set.read_set_digest,
            read_set.to_subject()["readSetDigest"],
        )
        self.assertEqual(
            "vm-a",
            read_set.to_subject()["vmId"],
        )
        for changed in (
            {"read_set_digest": digest("f")},
            {"request_resource_version": 0},
            {"request_hash": digest("f")},
            {"request_entity_digest": digest("f")},
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(DirectPathVerificationError):
                    replace(read_set, **changed)

    def test_binding_rejects_noncurrent_snapshot_policy_or_verifier(self) -> None:
        for change in (
            {"publisher_snapshot_digest": digest("f")},
            {"policy_digest": digest("f")},
            {"inventory_verifier_identity_digest": digest("f")},
        ):
            with self.subTest(change=change):
                with self.assertRaises(DirectPathVerificationError) as raised:
                    bind_authorization(
                        decision_digest=digest("e"),
                        dependencies=replace(dependencies(), **change),
                        current=authority(),
                        availability_read_set=availability_read_set(),
                        request_read_set=request_read_set(),
                        evaluated_at=CHECKED_AT,
                        valid_until=VALID_UNTIL,
                    )
                self.assertEqual(raised.exception.code, "STALE_AUTHORITY")


if __name__ == "__main__":
    unittest.main()
