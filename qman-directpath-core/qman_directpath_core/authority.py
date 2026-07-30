"""Two-layer dependency and current-authority binding.

The semantic dependency key is deliberately scoped to the selected capability
and qualification inputs.  A disjoint profile change can therefore leave that
cache key stable.  The admission authorization binds the complete current
authority vector; any root/ring/catalog/anchor/publisher advance invalidates an
old authorization before a side effect.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Iterable

from .canonical import SAFE_INTEGER, canonical_json_bytes, sha256_digest
from .errors import fail


DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
CAPABILITY_AUTHORITY_BOUNDARY = (
    "COMPONENT_STATIC_CAPABILITY_RELATIONSHIP_ONLY"
)
CAPABILITY_PRODUCT_AUTHORIZED = False
CAPABILITY_HARDWARE_PREMISE_AUTHORITY_BOUNDARY = (
    "COMPONENT_VERIFIED_INVENTORY_PREMISE_ONLY"
)
CAPABILITY_RESOURCE_PLAN_AUTHORITY_BOUNDARY = (
    "COMPONENT_CALLER_SUPPLIED_RESOURCE_PLAN_BYTES_ONLY"
)
CAPABILITY_QUALIFICATION_AUTHORITY_BOUNDARY = "COMPONENT_ONLY"
CAPABILITY_HOST_SNAPSHOT_ANCHOR_AUTHORITY_BOUNDARY = (
    "COMPONENT_EXTERNAL_BYTES_VERIFICATION_ONLY"
)
CAPABILITY_AUTHORIZATION_BLOCKERS = (
    "PRODUCT_HOST_SNAPSHOT_AUTHORITY_ADAPTER_REQUIRED",
    "PRODUCT_INVENTORY_COLLECTOR_PUBLISHER_REQUIRED",
    "PRODUCT_REPOSITORY_LEASE_CAS_REQUIRED",
    "PRODUCT_RESOURCE_PLANNER_REQUIRED",
    "TRUSTED_E4_ADAPTER_REQUIRED",
)


def _digest(value: str, path: str) -> str:
    if not isinstance(value, str) or DIGEST_RE.fullmatch(value) is None:
        fail("INVALID_DIGEST", path, "expected sha256:<64 lowercase hex>")
    return value


def _id(value: str, path: str) -> str:
    if not isinstance(value, str) or not value:
        fail("INVALID_ID", path, "expected a non-empty stable identifier")
    return value


def _positive(value: int, path: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 1
        or value > SAFE_INTEGER
    ):
        fail(
            "INVALID_SEQUENCE",
            path,
            "expected an interoperable-safe positive integer",
        )
    return value


def _utc(value: datetime, path: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        fail("TIME_INVALID", path, "expected a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def _timestamp(value: datetime, path: str) -> str:
    return _utc(value, path).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _digest_set(values: Iterable[str], path: str) -> tuple[str, ...]:
    result = tuple(values)
    for index, value in enumerate(result):
        _digest(value, f"{path}[{index}]")
    expected = tuple(sorted(set(result), key=canonical_json_bytes))
    if result != expected:
        fail(
            "NONCANONICAL_SET",
            path,
            "digest set must be unique and in canonical order",
        )
    return result


def _id_set(values: Iterable[str], path: str) -> tuple[str, ...]:
    result = tuple(values)
    for index, value in enumerate(result):
        _id(value, f"{path}[{index}]")
    expected = tuple(sorted(set(result), key=canonical_json_bytes))
    if result != expected:
        fail(
            "NONCANONICAL_SET",
            path,
            "identifier set must be unique and in canonical order",
        )
    return result


@dataclass(frozen=True, slots=True)
class CapabilityAuthorityDisposition:
    """Closed authority boundary carried across every component admission.

    This prevents an eligible component decision from losing the non-product
    provenance of its inventory, plan, qualification, and anchor premises when
    it is serialized into an operation-admission binding.
    """

    static_capability_context_digest: str
    hardware_premise_digest: str
    hardware_premise_authority_boundary: str
    resource_plan_context_digest: str
    resource_plan_hash: str
    resource_plan_authority_boundary: str
    qualification_binding_context_digest: str
    qualification_authority_boundary: str
    host_snapshot_anchor_binding_digest: str
    host_snapshot_anchor_authority_boundary: str
    authorization_blockers: tuple[str, ...]
    authority_boundary: str = CAPABILITY_AUTHORITY_BOUNDARY
    product_authorized: bool = CAPABILITY_PRODUCT_AUTHORIZED

    def __post_init__(self) -> None:
        for value, path in (
            (
                self.static_capability_context_digest,
                "authorityDisposition.staticCapabilityContextDigest",
            ),
            (
                self.hardware_premise_digest,
                "authorityDisposition.hardwarePremise.premiseDigest",
            ),
            (
                self.resource_plan_context_digest,
                "authorityDisposition.resourcePlan.contextDigest",
            ),
            (
                self.resource_plan_hash,
                "authorityDisposition.resourcePlan.planHash",
            ),
            (
                self.qualification_binding_context_digest,
                "authorityDisposition.qualification.bindingContextDigest",
            ),
            (
                self.host_snapshot_anchor_binding_digest,
                "authorityDisposition.hostSnapshotAnchor.bindingDigest",
            ),
        ):
            _digest(value, path)
        for value, path in (
            (
                self.hardware_premise_authority_boundary,
                "authorityDisposition.hardwarePremise.authorityBoundary",
            ),
            (
                self.resource_plan_authority_boundary,
                "authorityDisposition.resourcePlan.authorityBoundary",
            ),
            (
                self.qualification_authority_boundary,
                "authorityDisposition.qualification.authorityBoundary",
            ),
            (
                self.host_snapshot_anchor_authority_boundary,
                "authorityDisposition.hostSnapshotAnchor.authorityBoundary",
            ),
        ):
            _id(value, path)
        blockers = _id_set(
            self.authorization_blockers,
            "authorityDisposition.authorizationBlockers",
        )
        if blockers != CAPABILITY_AUTHORIZATION_BLOCKERS:
            fail(
                "AUTHORITY_DISPOSITION_INVALID",
                "authorityDisposition.authorizationBlockers",
                "component authority requires the complete closed blocker set",
            )
        object.__setattr__(self, "authorization_blockers", blockers)
        expected_premise_boundaries = (
            (
                self.hardware_premise_authority_boundary,
                CAPABILITY_HARDWARE_PREMISE_AUTHORITY_BOUNDARY,
                "authorityDisposition.hardwarePremise.authorityBoundary",
            ),
            (
                self.resource_plan_authority_boundary,
                CAPABILITY_RESOURCE_PLAN_AUTHORITY_BOUNDARY,
                "authorityDisposition.resourcePlan.authorityBoundary",
            ),
            (
                self.qualification_authority_boundary,
                CAPABILITY_QUALIFICATION_AUTHORITY_BOUNDARY,
                "authorityDisposition.qualification.authorityBoundary",
            ),
            (
                self.host_snapshot_anchor_authority_boundary,
                CAPABILITY_HOST_SNAPSHOT_ANCHOR_AUTHORITY_BOUNDARY,
                "authorityDisposition.hostSnapshotAnchor.authorityBoundary",
            ),
        )
        for actual, expected, path in expected_premise_boundaries:
            if actual != expected:
                fail(
                    "AUTHORITY_DISPOSITION_INVALID",
                    path,
                    "component premise authority boundary is not the closed value",
                )
        if (
            self.authority_boundary != CAPABILITY_AUTHORITY_BOUNDARY
            or self.product_authorized is not CAPABILITY_PRODUCT_AUTHORIZED
        ):
            fail(
                "AUTHORITY_DISPOSITION_INVALID",
                "authorityDisposition",
                "portable capability premises cannot claim product authority",
            )

    def to_subject(self) -> dict[str, object]:
        return {
            "authorityBoundary": self.authority_boundary,
            "productAuthorized": self.product_authorized,
            "authorizationBlockers": list(self.authorization_blockers),
            "staticCapabilityContextDigest": (
                self.static_capability_context_digest
            ),
            "premises": {
                "hardwarePremise": {
                    "premiseDigest": self.hardware_premise_digest,
                    "authorityBoundary": (
                        self.hardware_premise_authority_boundary
                    ),
                    "productAuthorized": False,
                },
                "resourcePlan": {
                    "contextDigest": self.resource_plan_context_digest,
                    "planHash": self.resource_plan_hash,
                    "authorityBoundary": (
                        self.resource_plan_authority_boundary
                    ),
                    "productAuthorized": False,
                },
                "qualification": {
                    "bindingContextDigest": (
                        self.qualification_binding_context_digest
                    ),
                    "authorityBoundary": (
                        self.qualification_authority_boundary
                    ),
                    "productAuthorized": False,
                },
                "hostSnapshotAnchor": {
                    "bindingDigest": (
                        self.host_snapshot_anchor_binding_digest
                    ),
                    "authorityBoundary": (
                        self.host_snapshot_anchor_authority_boundary
                    ),
                    "productAuthorized": False,
                },
            },
        }


@dataclass(frozen=True, slots=True)
class AvailabilityMemberVersion:
    """One selected member version observed by the availability authority."""

    device_uid: str
    device_generation: int
    resource_version: int

    def __post_init__(self) -> None:
        _id(self.device_uid, "availability.member.device_uid")
        _positive(
            self.device_generation,
            "availability.member.device_generation",
        )
        _positive(
            self.resource_version,
            "availability.member.resource_version",
        )

    def to_subject(self) -> dict[str, object]:
        return {
            "deviceUid": self.device_uid,
            "deviceGeneration": self.device_generation,
            "resourceVersion": self.resource_version,
        }


@dataclass(frozen=True, slots=True)
class AvailabilityReadSet:
    """Canonical selected-scope lease/quarantine predicate observation.

    ``authority_resource_version`` is useful only when the product repository
    advances it for every lease, quarantine, or member-generation mutation
    that can affect this selected bundle.  This value object verifies the
    closed bytes and digest; it cannot prove that an adapter used a
    serializable read or a real repository-wide predicate fence.
    """

    authority_id: str
    authority_resource_version: int
    bundle_digest: str
    member_versions: tuple[AvailabilityMemberVersion, ...]
    blocking_claim_digests: tuple[str, ...]
    blocking_quarantine_record_digests: tuple[str, ...]
    read_set_digest: str

    def __post_init__(self) -> None:
        _id(self.authority_id, "availability.authority_id")
        _positive(
            self.authority_resource_version,
            "availability.authority_resource_version",
        )
        _digest(self.bundle_digest, "availability.bundle_digest")
        members = tuple(self.member_versions)
        if not members:
            fail(
                "INVALID_AVAILABILITY_READ_SET",
                "availability.member_versions",
                "the selected bundle must contain at least one member",
            )
        for index, member in enumerate(members):
            if not isinstance(member, AvailabilityMemberVersion):
                fail(
                    "INVALID_AVAILABILITY_READ_SET",
                    f"availability.member_versions[{index}]",
                    "expected AvailabilityMemberVersion",
                )
        expected_members = tuple(
            sorted(
                members,
                key=lambda item: canonical_json_bytes(item.to_subject()),
            )
        )
        if members != expected_members or len(
            {member.device_uid for member in members}
        ) != len(members):
            fail(
                "NONCANONICAL_SET",
                "availability.member_versions",
                "members must have unique device UIDs in canonical order",
            )
        object.__setattr__(self, "member_versions", members)
        object.__setattr__(
            self,
            "blocking_claim_digests",
            _digest_set(
                self.blocking_claim_digests,
                "availability.blocking_claim_digests",
            ),
        )
        object.__setattr__(
            self,
            "blocking_quarantine_record_digests",
            _digest_set(
                self.blocking_quarantine_record_digests,
                "availability.blocking_quarantine_record_digests",
            ),
        )
        _digest(self.read_set_digest, "availability.read_set_digest")
        expected_digest = sha256_digest(
            canonical_json_bytes(self._subject(read_set_digest=None))
        )
        if self.read_set_digest != expected_digest:
            fail(
                "DIGEST_MISMATCH",
                "availability.read_set_digest",
                "digest does not match the null-hash canonical subject",
            )

    def _subject(self, *, read_set_digest: str | None) -> dict[str, object]:
        return {
            "subjectType": "AVAILABILITY_READ_SET",
            "schemaVersion": 1,
            "authorityId": self.authority_id,
            "authorityResourceVersion": self.authority_resource_version,
            "bundleDigest": self.bundle_digest,
            "memberVersions": [member.to_subject() for member in self.member_versions],
            "blockingClaimDigests": list(self.blocking_claim_digests),
            "blockingQuarantineRecordDigests": list(
                self.blocking_quarantine_record_digests
            ),
            "readSetDigest": read_set_digest,
        }

    def to_subject(self) -> dict[str, object]:
        """Return a fresh closed canonical projection."""

        return self._subject(read_set_digest=self.read_set_digest)

    @property
    def predicate_available(self) -> bool:
        """Return the repository predicate result, not full capability."""

        return not (
            self.blocking_claim_digests or self.blocking_quarantine_record_digests
        )


@dataclass(frozen=True, slots=True)
class RequestReadSet:
    """Canonical observation of one current persisted VM request row.

    This value binds the exact row identity and version that a product adapter
    supplied to the guarded evaluation.  It does not prove that the adapter
    performed a linearizable read or protected a later side effect with CAS.
    """

    authority_id: str
    vm_id: str
    request_version: int
    request_resource_version: int
    request_hash: str
    request_entity_digest: str
    read_set_digest: str

    def __post_init__(self) -> None:
        _id(self.authority_id, "request_read_set.authority_id")
        _id(self.vm_id, "request_read_set.vm_id")
        _positive(
            self.request_version,
            "request_read_set.request_version",
        )
        _positive(
            self.request_resource_version,
            "request_read_set.request_resource_version",
        )
        _digest(self.request_hash, "request_read_set.request_hash")
        _digest(
            self.request_entity_digest,
            "request_read_set.request_entity_digest",
        )
        _digest(
            self.read_set_digest,
            "request_read_set.read_set_digest",
        )
        expected_digest = sha256_digest(
            canonical_json_bytes(self._subject(read_set_digest=None))
        )
        if self.read_set_digest != expected_digest:
            fail(
                "DIGEST_MISMATCH",
                "request_read_set.read_set_digest",
                "digest does not match the null-hash canonical subject",
            )

    def _subject(self, *, read_set_digest: str | None) -> dict[str, object]:
        return {
            "subjectType": "REQUEST_READ_SET",
            "schemaVersion": 1,
            "authorityId": self.authority_id,
            "vmId": self.vm_id,
            "requestVersion": self.request_version,
            "requestResourceVersion": self.request_resource_version,
            "requestHash": self.request_hash,
            "requestEntityDigest": self.request_entity_digest,
            "readSetDigest": read_set_digest,
        }

    def to_subject(self) -> dict[str, object]:
        """Return a fresh closed canonical projection."""

        return self._subject(read_set_digest=self.read_set_digest)


@dataclass(frozen=True, slots=True)
class ScopedCapabilityDependencies:
    """Inputs that can change the selected capability's semantic conclusion."""

    # Exact publisher identity is retained for authorization currentness, but
    # deliberately excluded from ``semantic_digest``.  Availability/lease-only
    # publications may advance it without changing the owner-independent
    # hardware projection below.
    publisher_snapshot_digest: str
    hardware_snapshot_semantic_digest: str
    policy_digest: str
    # The exact resolved profile hash is retained in the decision wire and
    # changes with global catalog currentness.  The selective digest changes
    # only when the selected record, matching deny rule, or signer dependency
    # changes.
    qualification_profile_digest: str
    qualification_profile_semantic_digest: str
    qualification_record_digests: tuple[str, ...]
    qualification_signer_key_ids: tuple[str, ...]
    inventory_verifier_identity_digest: str
    dependency_bundle_digest: str
    dependency_bundle_semantic_digest: str
    reset_contract_digest: str
    closure_request_digest: str
    # This selected-scope lease/quarantine observation is currentness-only.
    # It is deliberately excluded from ``semantic_digest`` so a busy/free
    # transition never changes owner-independent capability semantics.
    availability_read_set_digest: str
    # The exact persisted request row observation is currentness-only.  It is
    # deliberately excluded from ``semantic_digest``: a resourceVersion-only
    # rewrite cannot change the canonical request semantics.
    request_read_set_digest: str
    request_digest: str

    def __post_init__(self) -> None:
        for field in (
            "publisher_snapshot_digest",
            "hardware_snapshot_semantic_digest",
            "policy_digest",
            "qualification_profile_digest",
            "qualification_profile_semantic_digest",
            "inventory_verifier_identity_digest",
            "dependency_bundle_digest",
            "dependency_bundle_semantic_digest",
            "reset_contract_digest",
            "closure_request_digest",
            "availability_read_set_digest",
            "request_read_set_digest",
            "request_digest",
        ):
            _digest(getattr(self, field), f"dependencies.{field}")
        object.__setattr__(
            self,
            "qualification_record_digests",
            _digest_set(
                self.qualification_record_digests,
                "dependencies.qualification_record_digests",
            ),
        )
        object.__setattr__(
            self,
            "qualification_signer_key_ids",
            _id_set(
                self.qualification_signer_key_ids,
                "dependencies.qualification_signer_key_ids",
            ),
        )

    def to_subject(self) -> dict[str, object]:
        """Return the scoped semantic cache subject, not an admission token."""

        return {
            "subjectType": "SCOPED_CAPABILITY_DEPENDENCIES",
            "schemaVersion": 1,
            "hardwareSnapshotSemanticDigest": (self.hardware_snapshot_semantic_digest),
            "policyDigest": self.policy_digest,
            "qualificationProfileSemanticDigest": (
                self.qualification_profile_semantic_digest
            ),
            "qualificationRecordDigests": list(self.qualification_record_digests),
            "qualificationSignerKeyIds": list(self.qualification_signer_key_ids),
            "inventoryVerifierIdentityDigest": (
                self.inventory_verifier_identity_digest
            ),
            "dependencyBundleSemanticDigest": (self.dependency_bundle_semantic_digest),
            "resetContractDigest": self.reset_contract_digest,
            "closureRequestDigest": self.closure_request_digest,
            "requestDigest": self.request_digest,
        }

    @property
    def semantic_digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_subject()))


@dataclass(frozen=True, slots=True)
class CurrentAuthorityVector:
    """Complete global currentness tuple fetched from independent authorities."""

    host_authority_id: str
    host_authority_resource_version: int
    publisher_snapshot_digest: str
    host_snapshot_anchor_authority_id: str
    host_snapshot_anchor_version: int
    host_snapshot_anchor_resource_version: int
    host_snapshot_anchor_digest: str
    host_snapshot_anchor_freshness_receipt_digest: str
    host_snapshot_anchor_binding_digest: str
    policy_authority_id: str
    policy_id: str
    policy_version: int
    policy_digest: str
    policy_authority_resource_version: int
    trust_root_digest: str
    key_ring_sequence: int
    key_ring_digest: str
    trust_anchor_version: int
    trust_anchor_digest: str
    catalog_id: str
    catalog_sequence: int
    catalog_digest: str
    catalog_anchor_version: int
    catalog_anchor_digest: str
    availability_authority_id: str
    availability_authority_resource_version: int
    availability_read_set_digest: str
    request_authority_id: str
    request_read_set_digest: str
    inventory_verification_receipt_digest: str
    inventory_verifier_identity_digest: str
    evidence_valid_until: datetime

    def __post_init__(self) -> None:
        for field in (
            "host_authority_id",
            "host_snapshot_anchor_authority_id",
            "policy_authority_id",
            "policy_id",
            "catalog_id",
            "availability_authority_id",
            "request_authority_id",
        ):
            _id(getattr(self, field), f"authority.{field}")
        for field in (
            "host_authority_resource_version",
            "host_snapshot_anchor_version",
            "host_snapshot_anchor_resource_version",
            "policy_version",
            "policy_authority_resource_version",
            "key_ring_sequence",
            "trust_anchor_version",
            "catalog_sequence",
            "catalog_anchor_version",
            "availability_authority_resource_version",
        ):
            _positive(getattr(self, field), f"authority.{field}")
        for field in (
            "publisher_snapshot_digest",
            "host_snapshot_anchor_digest",
            "host_snapshot_anchor_freshness_receipt_digest",
            "host_snapshot_anchor_binding_digest",
            "policy_digest",
            "trust_root_digest",
            "key_ring_digest",
            "trust_anchor_digest",
            "catalog_digest",
            "catalog_anchor_digest",
            "availability_read_set_digest",
            "request_read_set_digest",
            "inventory_verification_receipt_digest",
            "inventory_verifier_identity_digest",
        ):
            _digest(getattr(self, field), f"authority.{field}")
        object.__setattr__(
            self,
            "evidence_valid_until",
            _utc(
                self.evidence_valid_until,
                "authority.evidence_valid_until",
            ),
        )

    def to_subject(self) -> dict[str, object]:
        return {
            "subjectType": "CURRENT_AUTHORITY_VECTOR",
            "schemaVersion": 1,
            "hostAuthorityId": self.host_authority_id,
            "hostAuthorityResourceVersion": (self.host_authority_resource_version),
            "publisherSnapshotDigest": self.publisher_snapshot_digest,
            "hostSnapshotAnchorAuthorityId": (
                self.host_snapshot_anchor_authority_id
            ),
            "hostSnapshotAnchorVersion": self.host_snapshot_anchor_version,
            "hostSnapshotAnchorResourceVersion": (
                self.host_snapshot_anchor_resource_version
            ),
            "hostSnapshotAnchorDigest": self.host_snapshot_anchor_digest,
            "hostSnapshotAnchorFreshnessReceiptDigest": (
                self.host_snapshot_anchor_freshness_receipt_digest
            ),
            "hostSnapshotAnchorBindingDigest": (
                self.host_snapshot_anchor_binding_digest
            ),
            "policyAuthorityId": self.policy_authority_id,
            "policyId": self.policy_id,
            "policyVersion": self.policy_version,
            "policyDigest": self.policy_digest,
            "policyAuthorityResourceVersion": (self.policy_authority_resource_version),
            "trustRootDigest": self.trust_root_digest,
            "keyRingSequence": self.key_ring_sequence,
            "keyRingDigest": self.key_ring_digest,
            "trustAnchorVersion": self.trust_anchor_version,
            "trustAnchorDigest": self.trust_anchor_digest,
            "catalogId": self.catalog_id,
            "catalogSequence": self.catalog_sequence,
            "catalogDigest": self.catalog_digest,
            "catalogAnchorVersion": self.catalog_anchor_version,
            "catalogAnchorDigest": self.catalog_anchor_digest,
            "availabilityAuthorityId": self.availability_authority_id,
            "availabilityAuthorityResourceVersion": (
                self.availability_authority_resource_version
            ),
            "availabilityReadSetDigest": (self.availability_read_set_digest),
            "requestAuthorityId": self.request_authority_id,
            "requestReadSetDigest": self.request_read_set_digest,
            "inventoryVerificationReceiptDigest": (
                self.inventory_verification_receipt_digest
            ),
            "inventoryVerifierIdentityDigest": (
                self.inventory_verifier_identity_digest
            ),
            "evidenceValidUntil": _timestamp(
                self.evidence_valid_until,
                "authority.evidence_valid_until",
            ),
        }

    @property
    def vector_digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_subject()))


@dataclass(frozen=True, slots=True, init=False)
class BoundCapabilityAuthorization:
    """Trusted-process value; never a cross-process admission authority.

    There is intentionally no public constructor.  The value is returned only
    by the guarded evaluation path and cannot be recreated with
    :func:`dataclasses.replace`.  This is misuse resistance, not a security
    boundary: product side effects still require a live repository
    OperationLease/CAS authority.
    """

    decision_digest: str
    semantic_dependency_digest: str
    authority_vector_digest: str
    authority_disposition: CapabilityAuthorityDisposition
    evaluated_at: datetime
    valid_until: datetime

    def __post_init__(self) -> None:
        _digest(self.decision_digest, "authorization.decision_digest")
        _digest(
            self.semantic_dependency_digest,
            "authorization.semantic_dependency_digest",
        )
        _digest(
            self.authority_vector_digest,
            "authorization.authority_vector_digest",
        )
        if not isinstance(
            self.authority_disposition,
            CapabilityAuthorityDisposition,
        ):
            fail(
                "AUTHORITY_DISPOSITION_INVALID",
                "authorization.authority_disposition",
                "expected CapabilityAuthorityDisposition",
            )
        evaluated_at = _utc(
            self.evaluated_at,
            "authorization.evaluated_at",
        )
        valid_until = _utc(
            self.valid_until,
            "authorization.valid_until",
        )
        if evaluated_at >= valid_until:
            fail(
                "AUTHORIZATION_WINDOW_INVALID",
                "authorization.valid_until",
                "valid_until must be later than evaluated_at",
            )
        object.__setattr__(self, "evaluated_at", evaluated_at)
        object.__setattr__(self, "valid_until", valid_until)

    @classmethod
    def _create(
        cls,
        *,
        decision_digest: str,
        semantic_dependency_digest: str,
        authority_vector_digest: str,
        authority_disposition: CapabilityAuthorityDisposition,
        evaluated_at: datetime,
        valid_until: datetime,
    ) -> "BoundCapabilityAuthorization":
        instance = object.__new__(cls)
        object.__setattr__(instance, "decision_digest", decision_digest)
        object.__setattr__(
            instance,
            "semantic_dependency_digest",
            semantic_dependency_digest,
        )
        object.__setattr__(
            instance,
            "authority_vector_digest",
            authority_vector_digest,
        )
        object.__setattr__(
            instance,
            "authority_disposition",
            authority_disposition,
        )
        object.__setattr__(instance, "evaluated_at", evaluated_at)
        object.__setattr__(instance, "valid_until", valid_until)
        instance.__post_init__()
        return instance


def _bind_authorization(
    *,
    decision_digest: str,
    dependencies: ScopedCapabilityDependencies,
    current: CurrentAuthorityVector,
    availability_read_set: AvailabilityReadSet,
    request_read_set: RequestReadSet,
    authority_disposition: CapabilityAuthorityDisposition,
    evaluated_at: datetime,
    valid_until: datetime,
) -> BoundCapabilityAuthorization:
    """Internal binding after read_guard has rebuilt the exact decision."""

    _digest(decision_digest, "decision_digest")
    if not isinstance(availability_read_set, AvailabilityReadSet):
        fail(
            "INVALID_AVAILABILITY_READ_SET",
            "availability_read_set",
            "expected a verified AvailabilityReadSet value",
        )
    if not isinstance(request_read_set, RequestReadSet):
        fail(
            "INVALID_REQUEST_READ_SET",
            "request_read_set",
            "expected a verified RequestReadSet value",
        )
    if not isinstance(
        authority_disposition,
        CapabilityAuthorityDisposition,
    ):
        fail(
            "AUTHORITY_DISPOSITION_INVALID",
            "authority_disposition",
            "expected CapabilityAuthorityDisposition",
        )
    if (
        availability_read_set.read_set_digest
        != dependencies.availability_read_set_digest
    ):
        fail(
            "STALE_AUTHORITY",
            "dependencies.availability_read_set_digest",
            "selected availability read set does not match dependencies",
        )
    if availability_read_set.bundle_digest != dependencies.dependency_bundle_digest:
        fail(
            "STALE_AUTHORITY",
            "availability_read_set.bundle_digest",
            "availability predicate does not cover the selected bundle",
        )
    if request_read_set.read_set_digest != (dependencies.request_read_set_digest):
        fail(
            "STALE_AUTHORITY",
            "dependencies.request_read_set_digest",
            "selected request read set does not match dependencies",
        )
    if request_read_set.request_hash != dependencies.request_digest:
        fail(
            "STALE_AUTHORITY",
            "request_read_set.request_hash",
            "request row does not contain the selected request",
        )
    if dependencies.publisher_snapshot_digest != current.publisher_snapshot_digest:
        fail(
            "STALE_AUTHORITY",
            "dependencies.publisher_snapshot_digest",
            "selected snapshot is not the current host authority snapshot",
        )
    if dependencies.policy_digest != current.policy_digest:
        fail(
            "STALE_AUTHORITY",
            "dependencies.policy_digest",
            "selected policy is not the current authority policy",
        )
    if (
        dependencies.inventory_verifier_identity_digest
        != current.inventory_verifier_identity_digest
    ):
        fail(
            "STALE_AUTHORITY",
            "dependencies.inventory_verifier_identity_digest",
            "selected verifier is not the current verifier identity",
        )
    if (
        dependencies.availability_read_set_digest
        != current.availability_read_set_digest
    ):
        fail(
            "STALE_AUTHORITY",
            "dependencies.availability_read_set_digest",
            "selected availability read set is not current",
        )
    if dependencies.request_read_set_digest != current.request_read_set_digest:
        fail(
            "STALE_AUTHORITY",
            "dependencies.request_read_set_digest",
            "selected request read set is not current",
        )
    if (
        availability_read_set.authority_id != current.availability_authority_id
        or availability_read_set.authority_resource_version
        != current.availability_authority_resource_version
    ):
        fail(
            "STALE_AUTHORITY",
            "availability_read_set.authority",
            "availability predicate fence is not the current authority",
        )
    if request_read_set.authority_id != current.request_authority_id:
        fail(
            "STALE_AUTHORITY",
            "request_read_set.authority_id",
            "request row observation is not from the current authority",
        )
    normalized_evaluated_at = _utc(evaluated_at, "evaluated_at")
    normalized_valid_until = _utc(valid_until, "valid_until")
    if (
        normalized_evaluated_at >= current.evidence_valid_until
        or normalized_valid_until > current.evidence_valid_until
    ):
        fail(
            "STALE_AUTHORITY",
            "valid_until",
            (
                "authorization window exceeds the verified trust, catalog, "
                "profile, or freshness evidence horizon"
            ),
        )
    return BoundCapabilityAuthorization._create(
        decision_digest=decision_digest,
        semantic_dependency_digest=dependencies.semantic_digest,
        authority_vector_digest=current.vector_digest,
        authority_disposition=authority_disposition,
        evaluated_at=normalized_evaluated_at,
        valid_until=normalized_valid_until,
    )


def assert_current(
    authorization: BoundCapabilityAuthorization,
    current: CurrentAuthorityVector,
    *,
    at: datetime,
    expected_decision_digest: str,
    dependencies: ScopedCapabilityDependencies,
) -> None:
    """Fail before schedule/reserve/attach when authority or time moved."""

    _digest(expected_decision_digest, "expected_decision_digest")
    if authorization.decision_digest != expected_decision_digest:
        fail(
            "STALE_AUTHORITY",
            "authorization.decision_digest",
            "authorization belongs to a different capability decision",
        )
    if authorization.semantic_dependency_digest != dependencies.semantic_digest:
        fail(
            "STALE_AUTHORITY",
            "authorization.semantic_dependency_digest",
            "authorization belongs to a different semantic dependency set",
        )
    if authorization.authority_vector_digest != current.vector_digest:
        fail(
            "STALE_AUTHORITY",
            "authorization.authority_vector_digest",
            "authority vector changed after capability evaluation",
        )
    checked_at = _utc(at, "authorization.current_time")
    if not authorization.evaluated_at <= checked_at < authorization.valid_until:
        fail(
            "STALE_AUTHORITY",
            "authorization.valid_until",
            "authorization is outside its verified validity window",
        )


def semantic_cache_reusable(
    authorization: BoundCapabilityAuthorization,
    dependencies: ScopedCapabilityDependencies,
) -> bool:
    """Return cache equivalence only; this never authorizes a side effect."""

    return authorization.semantic_dependency_digest == dependencies.semantic_digest
