"""Fail-closed trust and qualification verification for DirectPath.

The functions in this module are deliberately side-effect free.  They verify
documents supplied by an integration layer, but they do not fetch, publish, or
advance either monotonic authority.  In particular, passing an object named
``external_*_anchor`` is a caller assertion about provenance; production
integration MUST obtain those bytes and the nonce-bound freshness response
directly from an authority outside the target, evidence, and controller trust
domains.

All signed content uses the repository's closed CANONICAL-JSON-V1 profile and
real Ed25519 verification from ``cryptography``.  There is no compatibility
fallback, permissive parser, or synthetic signature mode.
"""

from __future__ import annotations

import base64
import binascii
import copy
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import (
    CanonicalizationError,
    canonical_json_bytes,
    load_canonical_json,
    sha256_digest,
)
from .contracts import ContractSchemas
from .errors import fail, require
from ._verified import FactoryVerified, require_factory_verified


JsonDocument = Mapping[str, Any] | bytes | bytearray | memoryview

_TRUST_RING_DOMAIN: Final = b"QMAN-DIRECTPATH/TRUST-KEY-RING/V1\x00"
_FRESHNESS_DOMAIN: Final = b"QMAN-DIRECTPATH/ANCHOR-FRESHNESS/V1\x00"
_CATALOG_DOMAIN: Final = b"QMAN-DIRECTPATH/SUPPORTED-CATALOG/V1\x00"
_CATALOG_RECEIPT_DOMAIN: Final = (
    b"QMAN-DIRECTPATH/CATALOG-ROLLBACK-ANCHOR-RECEIPT/V1\x00"
)
_QUALIFICATION_DOMAIN: Final = b"QMAN-DIRECTPATH/QUALIFICATION-RECORD/V1\x00"
_MAX_FRESHNESS_SIGNATURE_FUTURE_SKEW: Final = timedelta(seconds=30)

_TRUST_ANCHOR_SCHEMA: Final = "contracts/directpath-trust-rollback-anchor.schema.json"
_CATALOG_ANCHOR_SCHEMA: Final = (
    "contracts/directpath-catalog-rollback-anchor.schema.json"
)

_SEPARATED_ROLE_PAIRS: Final = (
    ("QUALIFICATION_ENGINEERING", "PRODUCT_RELEASE"),
    ("HOST_RELEASE_EVIDENCE", "CONTROL_REPOSITORY_EVIDENCE"),
    ("TARGET_ARCHITECT", "SECURITY"),
    ("TARGET_ARCHITECT", "TEST"),
    ("SECURITY", "TEST"),
)


@dataclass(frozen=True, slots=True, init=False)
class VerifiedKey(FactoryVerified):
    """One authenticated role key from a specific key-ring revision."""

    key_id: str
    principal_id: str
    public_key_base64url: str
    roles: tuple[str, ...]
    not_before: datetime
    not_after: datetime
    revoked_at: datetime | None


@dataclass(frozen=True, slots=True, init=False)
class _VerifiedRing(FactoryVerified):
    key_ring_id: str
    sequence: int
    digest: str
    previous_digest: str | None
    not_before: datetime
    expires_at: datetime
    revoked_key_ids: frozenset[str]
    keys: Mapping[str, VerifiedKey]


@dataclass(frozen=True, slots=True, init=False)
class VerifiedTrustContext(FactoryVerified):
    """Immutable result of root, history, anchor, and freshness verification.

    ``keys`` is authenticated metadata, not a use authorization.  Call
    :meth:`authorized_key` with an evaluator time and required role before
    using current-ring key material for a new operation.
    """

    root_set_id: str
    root_set_digest: str
    key_ring_id: str
    key_ring_sequence: int
    key_ring_digest: str
    verified_history_digest: str
    trust_anchor_digest: str
    trust_anchor_version: int
    trust_anchor_resource_version: int
    trust_anchor_authority_id: str
    freshness_receipt_digest: str
    freshness_anchor_path: str
    freshness_expires_at: datetime
    verified_at: datetime
    context_digest: str
    keys: Mapping[str, VerifiedKey]
    _root_set: Mapping[str, Any] = field(repr=False, compare=False)
    _rings: tuple[_VerifiedRing, ...] = field(repr=False, compare=False)

    def authorized_key(
        self,
        key_id: str,
        *,
        required_role: str,
        at: datetime,
    ) -> VerifiedKey:
        """Authorize one current-ring key for a role at an explicit time."""

        try:
            key = self.keys[key_id]
        except KeyError:
            fail(
                "SIGNER_UNKNOWN",
                "trust.keys",
                f"key {key_id!r} is absent from the authenticated current ring",
            )
        evaluation_time = _utc_now(at, "trust.keys.at")
        require(
            self.verified_at <= evaluation_time <= self.freshness_expires_at,
            "TRUST_CONTEXT_STALE",
            "trust.keys.at",
            "key authorization time is outside the verified freshness window",
        )
        require(
            isinstance(required_role, str) and required_role in key.roles,
            "SIGNER_ROLE_INVALID",
            "trust.keys",
            f"key {key_id!r} lacks required role {required_role!r}",
        )
        current = self._rings[-1]
        require(
            current.not_before <= evaluation_time < current.expires_at,
            "KEY_RING_NOT_CURRENT",
            "trust.keys.at",
            "the authenticated current ring is inactive at evaluator time",
        )
        require(
            key.not_before <= evaluation_time < key.not_after,
            "SIGNER_INACTIVE",
            "trust.keys.at",
            f"key {key_id!r} is inactive at evaluator time",
        )
        require(
            key_id not in current.revoked_key_ids,
            "SIGNER_REVOKED",
            "trust.keys",
            f"key {key_id!r} is in the current ring revocation set",
        )
        if key.revoked_at is not None:
            require(
                evaluation_time < key.revoked_at,
                "SIGNER_REVOKED",
                "trust.keys.at",
                f"key {key_id!r} is revoked at evaluator time",
            )
        return key


@dataclass(frozen=True, slots=True, init=False)
class QualificationProfileDependency(FactoryVerified):
    """Selective invalidation identity for one verified qualification profile.

    ``dependency_digest`` intentionally excludes unrelated record membership
    and the catalog sequence/digest.  Removal of this record removes the
    dependency from the resolved context; changes to this record, a matching
    deny selector, catalog authority/validity policy, or trust ring change the
    digest.  ``VerifiedQualificationContext.context_digest`` remains the exact
    global snapshot identity and changes for every catalog revision.
    """

    qualification_record_id: str
    qualification_record_digest: str
    qualification_record_canonical_digest: str
    exact_qualification_key: str
    platform_profile_hash: str
    qualification_signer_key_id: str
    qualification_signer_principal_id: str
    selector_digests: tuple[tuple[str, str], ...]
    applicable_deny_entry_digests: tuple[str, ...]
    not_before: datetime
    expires_at: datetime
    dependency_digest: str


@dataclass(frozen=True, slots=True, init=False)
class VerifiedQualificationContext(FactoryVerified):
    """Immutable current supported-catalog and profile resolution."""

    trust: VerifiedTrustContext
    catalog_id: str
    catalog_sequence: int
    catalog_digest: str
    catalog_canonical_digest: str
    product_release_signer_key_id: str
    product_release_signer_principal_id: str
    catalog_anchor_digest: str
    catalog_anchor_version: int
    catalog_anchor_resource_version: int
    catalog_anchor_authority_id: str
    catalog_anchor_receipt_digest: str
    freshness_receipt_digest: str
    freshness_verifier_nonce: str
    freshness_observed_at: datetime
    freshness_expires_at: datetime
    verified_at: datetime
    context_digest: str
    profiles: tuple[QualificationProfileDependency, ...]
    profiles_by_exact_key: Mapping[str, QualificationProfileDependency]

    def profile(self, exact_qualification_key: str) -> QualificationProfileDependency:
        """Resolve one exact supported profile; absence is a deny."""

        try:
            return self.profiles_by_exact_key[exact_qualification_key]
        except KeyError:
            fail(
                "QUALIFICATION_PROFILE_NOT_SUPPORTED",
                "qualification.profiles",
                f"no current verified profile for {exact_qualification_key!r}",
            )


def _utc_now(value: datetime, path: str = "now") -> datetime:
    require(
        isinstance(value, datetime),
        "TIME_INVALID",
        path,
        "an aware datetime is required",
    )
    require(
        value.tzinfo is not None and value.utcoffset() is not None,
        "TIME_INVALID",
        path,
        "a timezone-aware datetime is required",
    )
    return value.astimezone(timezone.utc)


def _timestamp(value: Any, path: str) -> datetime:
    require(
        isinstance(value, str),
        "TIME_INVALID",
        path,
        "expected the contract timestamp string",
    )
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        fail("TIME_INVALID", path, f"invalid contract timestamp: {exc}")
    return parsed.replace(tzinfo=timezone.utc)


def _document(value: JsonDocument, path: str) -> tuple[dict[str, Any], bytes]:
    """Load one document and retain the exact canonical bytes used for binding."""

    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        try:
            loaded = load_canonical_json(raw)
        except CanonicalizationError as exc:
            fail("CANONICAL_JSON_INVALID", path, str(exc))
    elif isinstance(value, Mapping):
        try:
            raw = canonical_json_bytes(value)
            # Reparse the exact bound bytes.  A caller-supplied Mapping is
            # never traversed a second time to create a potentially different
            # validation object.
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


def _projection_digest(
    document: Mapping[str, Any],
    *,
    null_fields: Sequence[str] = (),
    empty_array_fields: Sequence[str] = (),
    path: str,
) -> tuple[str, bytes]:
    projection = copy.deepcopy(dict(document))
    for name in null_fields:
        projection[name] = None
    for name in empty_array_fields:
        projection[name] = []
    try:
        raw = canonical_json_bytes(projection)
    except (CanonicalizationError, TypeError, ValueError) as exc:
        fail("CANONICAL_JSON_INVALID", path, str(exc))
    return sha256_digest(raw), raw


def _require_digest(
    declared: Any, actual: str, path: str, code: str = "DIGEST_MISMATCH"
) -> None:
    require(
        declared == actual,
        code,
        path,
        f"declared {declared!r}, computed {actual}",
    )


def _decode_base64url(value: Any, expected_size: int, path: str) -> bytes:
    require(
        isinstance(value, str) and "=" not in value,
        "BASE64URL_INVALID",
        path,
        "expected unpadded base64url text",
    )
    try:
        decoded = base64.b64decode(
            value + "=" * ((-len(value)) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        fail("BASE64URL_INVALID", path, str(exc))
    require(
        len(decoded) == expected_size,
        "BASE64URL_INVALID",
        path,
        f"expected {expected_size} decoded bytes, got {len(decoded)}",
    )
    require(
        base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") == value,
        "BASE64URL_INVALID",
        path,
        "encoding is not canonical unpadded base64url",
    )
    return decoded


def _verify_ed25519(
    public_key: Any, signature: Any, preimage: bytes, path: str
) -> None:
    public_bytes = _decode_base64url(public_key, 32, f"{path}.publicKey")
    require(
        isinstance(signature, str) and signature.startswith("ed25519:"),
        "SIGNATURE_INVALID",
        f"{path}.signature",
        "expected an ed25519: signature",
    )
    signature_bytes = _decode_base64url(
        signature[len("ed25519:") :], 64, f"{path}.signature"
    )
    try:
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(
            signature_bytes, preimage
        )
    except (InvalidSignature, ValueError) as exc:
        fail("SIGNATURE_INVALID", path, f"Ed25519 verification failed: {exc}")


def _canonical_order(
    values: Sequence[Any], path: str, *, key: str | None = None
) -> None:
    try:
        ordering = [
            canonical_json_bytes(item[key] if key is not None else item)
            for item in values
        ]
    except (KeyError, TypeError, CanonicalizationError) as exc:
        fail("CANONICAL_ORDER_INVALID", path, f"cannot derive order key: {exc}")
    require(
        ordering == sorted(ordering) and len(ordering) == len(set(ordering)),
        "CANONICAL_ORDER_INVALID",
        path,
        "values must be unique and in canonical ascending order",
    )


def _schema_hash(schemas: ContractSchemas, schema_ref: str, path: str) -> str:
    return schemas.digest_for_ref(schema_ref, path=path)


def _root_key_map(root_set: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {
        item["keyId"]: item for item in root_set["keys"] if isinstance(item, Mapping)
    }


def _validate_root_set(
    schemas: ContractSchemas,
    document: JsonDocument,
    pinned_digest: str,
) -> tuple[dict[str, Any], bytes]:
    root_set, raw = _document(document, "trust.rootSet")
    schemas.validate("root_set", root_set, "trust.rootSet")
    digest, _ = _projection_digest(
        root_set, null_fields=("rootSetDigest",), path="trust.rootSet"
    )
    _require_digest(
        root_set.get("rootSetDigest"),
        digest,
        "trust.rootSet.rootSetDigest",
        "TRUST_ROOT_DIGEST_INVALID",
    )
    require(
        pinned_digest == digest,
        "TRUST_ROOT_PIN_MISMATCH",
        "trust.pinnedRootDigest",
        f"independent pin {pinned_digest!r} does not equal {digest}",
    )

    keys = root_set["keys"]
    _canonical_order(keys, "trust.rootSet.keys", key="keyId")
    allowed = root_set["verificationPolicy"]["allowedKeyIds"]
    _canonical_order(allowed, "trust.rootSet.verificationPolicy.allowedKeyIds")

    key_ids: set[str] = set()
    principals: set[str] = set()
    materials: set[bytes] = set()
    for index, key in enumerate(keys):
        path = f"trust.rootSet.keys[{index}]"
        key_id = key["keyId"]
        material = _decode_base64url(
            key["publicKeyBase64Url"], 32, f"{path}.publicKeyBase64Url"
        )
        require(
            key_id not in key_ids,
            "TRUST_ROOT_INVALID",
            f"{path}.keyId",
            "duplicate root key ID",
        )
        require(
            key["principalId"] not in principals,
            "TRUST_ROOT_INVALID",
            f"{path}.principalId",
            "one offline custody principal may contribute only one root vote",
        )
        require(
            material not in materials,
            "TRUST_ROOT_INVALID",
            f"{path}.publicKeyBase64Url",
            "root key material is reused",
        )
        require(
            _timestamp(key["notBefore"], f"{path}.notBefore")
            < _timestamp(key["notAfter"], f"{path}.notAfter"),
            "TRUST_ROOT_INVALID",
            path,
            "notBefore must precede notAfter",
        )
        key_ids.add(key_id)
        principals.add(key["principalId"])
        materials.add(material)
    require(
        set(allowed) == key_ids,
        "TRUST_ROOT_POLICY_INVALID",
        "trust.rootSet.verificationPolicy.allowedKeyIds",
        "allowed keys must equal the exact root key set",
    )
    threshold = root_set["verificationPolicy"]["requiredSignatures"]
    require(
        threshold <= len(principals),
        "TRUST_ROOT_POLICY_INVALID",
        "trust.rootSet.verificationPolicy.requiredSignatures",
        "threshold exceeds distinct eligible root principals",
    )
    return root_set, raw


def _verify_root_quorum(
    root_set: Mapping[str, Any],
    signatures: Sequence[Mapping[str, Any]],
    *,
    digest_field: str,
    digest: str,
    domain: bytes,
    path: str,
    require_algorithm: bool = False,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> None:
    _canonical_order(signatures, path, key="rootKeyId")
    roots = _root_key_map(root_set)
    allowed = set(root_set["verificationPolicy"]["allowedKeyIds"])
    threshold = root_set["verificationPolicy"]["requiredSignatures"]
    principals: set[str] = set()
    materials: set[str] = set()

    for index, signature in enumerate(signatures):
        item_path = f"{path}[{index}]"
        root_id = signature["rootKeyId"]
        require(
            not require_algorithm or signature.get("algorithm") == "Ed25519",
            "SIGNATURE_ALGORITHM_INVALID",
            f"{item_path}.algorithm",
            "only Ed25519 is accepted",
        )
        require(
            root_id in allowed and root_id in roots,
            "ROOT_SIGNER_UNAUTHORIZED",
            f"{item_path}.rootKeyId",
            "root key is outside the independently pinned quorum policy",
        )
        root = roots[root_id]
        signed_at = _timestamp(signature["signedAt"], f"{item_path}.signedAt")
        root_before = _timestamp(root["notBefore"], f"{item_path}.root.notBefore")
        root_after = _timestamp(root["notAfter"], f"{item_path}.root.notAfter")
        require(
            root_before <= signed_at < root_after,
            "ROOT_SIGNER_INACTIVE",
            item_path,
            "root key was not active at signedAt",
        )
        if not_before is not None:
            require(
                signed_at >= not_before,
                "SIGNATURE_TIME_INVALID",
                f"{item_path}.signedAt",
                "signature predates the permitted signing window",
            )
        if not_after is not None:
            require(
                signed_at <= not_after,
                "SIGNATURE_TIME_INVALID",
                f"{item_path}.signedAt",
                "signature follows the permitted signing window",
            )
        subject = {
            "rootKeyId": root_id,
            "signedAt": signature["signedAt"],
            digest_field: digest,
        }
        _verify_ed25519(
            root["publicKeyBase64Url"],
            signature["signature"],
            domain + canonical_json_bytes(subject),
            item_path,
        )
        principals.add(root["principalId"])
        materials.add(root["publicKeyBase64Url"])

    require(
        min(len(principals), len(materials)) >= threshold,
        "ROOT_QUORUM_NOT_MET",
        path,
        (
            f"{len(principals)} distinct valid principals and "
            f"{len(materials)} key materials; {threshold} required"
        ),
    )


def _validate_role_separation(keys: Sequence[Mapping[str, Any]], path: str) -> None:
    principals_by_role: dict[str, set[str]] = {}
    materials: set[str] = set()
    key_ids: set[str] = set()
    for index, key in enumerate(keys):
        item_path = f"{path}[{index}]"
        _canonical_order(key["roles"], f"{item_path}.roles")
        require(
            key["keyId"] not in key_ids,
            "KEY_RING_IDENTITY_INVALID",
            f"{item_path}.keyId",
            "duplicate key ID",
        )
        require(
            key["publicKeyBase64Url"] not in materials,
            "KEY_RING_IDENTITY_INVALID",
            f"{item_path}.publicKeyBase64Url",
            "Ed25519 material is reused by another key",
        )
        key_ids.add(key["keyId"])
        materials.add(key["publicKeyBase64Url"])
        for role in key["roles"]:
            principals_by_role.setdefault(role, set()).add(key["principalId"])
        role_set = set(key["roles"])
        for left, right in _SEPARATED_ROLE_PAIRS:
            require(
                not {left, right}.issubset(role_set),
                "SEPARATION_OF_DUTIES_VIOLATION",
                f"{item_path}.roles",
                f"{left} and {right} cannot share one key",
            )

    for left, right in _SEPARATED_ROLE_PAIRS:
        overlap = principals_by_role.get(left, set()) & principals_by_role.get(
            right, set()
        )
        require(
            not overlap,
            "SEPARATION_OF_DUTIES_VIOLATION",
            path,
            f"{left} and {right} share principals {sorted(overlap)}",
        )


def _validate_ring(
    schemas: ContractSchemas,
    document: JsonDocument,
    root_set: Mapping[str, Any],
    index: int,
) -> tuple[dict[str, Any], bytes, _VerifiedRing]:
    path = f"trust.keyRingDocuments[{index}]"
    ring, raw = _document(document, path)
    schemas.validate("key_ring", ring, path)
    _canonical_order(ring["keys"], f"{path}.keys", key="keyId")
    _canonical_order(ring["revokedKeyIds"], f"{path}.revokedKeyIds")
    _canonical_order(ring["rootSignatures"], f"{path}.rootSignatures", key="rootKeyId")
    _validate_role_separation(ring["keys"], f"{path}.keys")

    ring_before = _timestamp(ring["notBefore"], f"{path}.notBefore")
    ring_after = _timestamp(ring["expiresAt"], f"{path}.expiresAt")
    require(
        ring_before < ring_after,
        "KEY_RING_TIME_INVALID",
        path,
        "notBefore must precede expiresAt",
    )
    verified_keys: dict[str, VerifiedKey] = {}
    for number, key in enumerate(ring["keys"]):
        key_path = f"{path}.keys[{number}]"
        _decode_base64url(
            key["publicKeyBase64Url"], 32, f"{key_path}.publicKeyBase64Url"
        )
        before = _timestamp(key["notBefore"], f"{key_path}.notBefore")
        after = _timestamp(key["notAfter"], f"{key_path}.notAfter")
        require(
            before < after,
            "KEY_VALIDITY_INVALID",
            key_path,
            "notBefore must precede notAfter",
        )
        revoked_at = (
            _timestamp(key["revokedAtOrNull"], f"{key_path}.revokedAtOrNull")
            if key["revokedAtOrNull"] is not None
            else None
        )
        verified_keys[key["keyId"]] = VerifiedKey._construct(
            key_id=key["keyId"],
            principal_id=key["principalId"],
            public_key_base64url=key["publicKeyBase64Url"],
            roles=tuple(key["roles"]),
            not_before=before,
            not_after=after,
            revoked_at=revoked_at,
        )

    digest, _ = _projection_digest(
        ring,
        null_fields=("keyRingDigest",),
        empty_array_fields=("rootSignatures",),
        path=f"{path}.digestProjection",
    )
    _require_digest(
        ring["keyRingDigest"],
        digest,
        f"{path}.keyRingDigest",
        "KEY_RING_DIGEST_INVALID",
    )
    _verify_root_quorum(
        root_set,
        ring["rootSignatures"],
        digest_field="keyRingDigest",
        digest=digest,
        domain=_TRUST_RING_DOMAIN,
        path=f"{path}.rootSignatures",
    )
    return (
        ring,
        raw,
        _VerifiedRing._construct(
            key_ring_id=ring["keyRingId"],
            sequence=ring["keyRingSequence"],
            digest=digest,
            previous_digest=ring["previousKeyRingDigest"],
            not_before=ring_before,
            expires_at=ring_after,
            revoked_key_ids=frozenset(ring["revokedKeyIds"]),
            keys=MappingProxyType(verified_keys),
        ),
    )


def _deep_freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _deep_freeze(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_deep_freeze(item) for item in value)
    return value


def _validate_ring_history(
    schemas: ContractSchemas,
    documents: Sequence[JsonDocument],
    root_set: Mapping[str, Any],
    now: datetime,
) -> tuple[
    tuple[dict[str, Any], ...],
    tuple[bytes, ...],
    tuple[_VerifiedRing, ...],
    str,
]:
    require(
        isinstance(documents, Sequence)
        and not isinstance(documents, (str, bytes, bytearray, memoryview))
        and len(documents) > 0,
        "KEY_RING_HISTORY_INCOMPLETE",
        "trust.keyRingDocuments",
        "the complete non-empty sequence 1..current is required",
    )
    loaded: list[dict[str, Any]] = []
    raw_documents: list[bytes] = []
    rings: list[_VerifiedRing] = []
    for index, document in enumerate(documents):
        ring_document, raw, verified = _validate_ring(
            schemas, document, root_set, index
        )
        loaded.append(ring_document)
        raw_documents.append(raw)
        rings.append(verified)

    key_ring_id = rings[0].key_ring_id
    previous_digest: str | None = None
    seen_ring_digests: set[str] = set()
    seen_key_identity: dict[str, tuple[str, str]] = {}
    seen_material_identity: dict[str, tuple[str, str]] = {}
    previous_keys: Mapping[str, VerifiedKey] = MappingProxyType({})
    permanently_absent: set[str] = set()
    revoked_ids: set[str] = set()
    ever_seen_ids: set[str] = set()

    for index, ring in enumerate(rings):
        path = f"trust.keyRingDocuments[{index}]"
        for number, signature in enumerate(loaded[index]["rootSignatures"]):
            require(
                _timestamp(
                    signature["signedAt"],
                    f"{path}.rootSignatures[{number}].signedAt",
                )
                <= now,
                "SIGNATURE_TIME_INVALID",
                f"{path}.rootSignatures[{number}].signedAt",
                "authenticated key-ring signature is future-dated",
            )
        expected_sequence = index + 1
        require(
            ring.sequence == expected_sequence,
            "KEY_RING_HISTORY_GAP",
            f"{path}.keyRingSequence",
            f"expected exact sequence {expected_sequence}, got {ring.sequence}",
        )
        require(
            ring.key_ring_id == key_ring_id,
            "KEY_RING_HISTORY_FORK",
            f"{path}.keyRingId",
            "keyRingId changed inside one history",
        )
        require(
            ring.previous_digest == previous_digest,
            "KEY_RING_HISTORY_FORK",
            f"{path}.previousKeyRingDigest",
            f"expected {previous_digest!r}, got {ring.previous_digest!r}",
        )
        require(
            ring.digest not in seen_ring_digests,
            "KEY_RING_HISTORY_FORK",
            f"{path}.keyRingDigest",
            "a ring digest is reused at another sequence",
        )
        seen_ring_digests.add(ring.digest)
        previous_digest = ring.digest

        current_ids = set(ring.keys)
        reappeared = current_ids & permanently_absent
        require(
            not reappeared,
            "KEY_RING_IDENTITY_REAPPEARED",
            f"{path}.keys",
            f"removed keys reappeared: {sorted(reappeared)}",
        )
        permanently_absent.update(set(previous_keys) - current_ids)

        require(
            revoked_ids.issubset(ring.revoked_key_ids),
            "KEY_RING_REVOCATION_ROLLBACK",
            f"{path}.revokedKeyIds",
            "the revocation set is not monotonic",
        )
        require(
            ring.revoked_key_ids.issubset(ever_seen_ids | current_ids),
            "KEY_RING_REVOCATION_INVALID",
            f"{path}.revokedKeyIds",
            "a key cannot be revoked before it appears in authenticated history",
        )
        revoked_ids.update(ring.revoked_key_ids)
        ever_seen_ids.update(current_ids)

        for key_id, key in ring.keys.items():
            identity = (key.principal_id, key.public_key_base64url)
            prior_identity = seen_key_identity.get(key_id)
            require(
                prior_identity is None or prior_identity == identity,
                "KEY_RING_IDENTITY_CHANGED",
                f"{path}.keys[{key_id!r}]",
                "an existing keyId changed principal or Ed25519 material",
            )
            seen_key_identity[key_id] = identity

            material_identity = (key_id, key.principal_id)
            prior_material_identity = seen_material_identity.get(
                key.public_key_base64url
            )
            require(
                prior_material_identity is None
                or prior_material_identity == material_identity,
                "KEY_RING_IDENTITY_CHANGED",
                f"{path}.keys[{key_id!r}].publicKeyBase64Url",
                "Ed25519 material changed key or principal identity",
            )
            seen_material_identity[key.public_key_base64url] = material_identity

            previous = previous_keys.get(key_id)
            if previous is not None:
                require(
                    key.not_before >= previous.not_before,
                    "KEY_VALIDITY_EXTENDED",
                    f"{path}.keys[{key_id!r}].notBefore",
                    "in-place validity cannot begin earlier",
                )
                require(
                    key.not_after <= previous.not_after,
                    "KEY_VALIDITY_EXTENDED",
                    f"{path}.keys[{key_id!r}].notAfter",
                    "in-place validity cannot be extended",
                )
                if previous.revoked_at is not None:
                    require(
                        key.revoked_at == previous.revoked_at,
                        "KEY_RING_REVOCATION_ROLLBACK",
                        f"{path}.keys[{key_id!r}].revokedAtOrNull",
                        "per-key revocation was cleared or changed",
                    )
        previous_keys = ring.keys

    current = rings[-1]
    require(
        current.not_before <= now < current.expires_at,
        "KEY_RING_NOT_CURRENT",
        "trust.keyRingDocuments[-1]",
        "the authenticated current ring is outside its validity interval",
    )
    history_projection = {
        "profileVersion": 1,
        "rootSetDigest": root_set["rootSetDigest"],
        "keyRingId": key_ring_id,
        "rings": [
            {
                "keyRingSequence": ring.sequence,
                "keyRingDigest": ring.digest,
                "previousKeyRingDigest": ring.previous_digest,
            }
            for ring in rings
        ],
    }
    history_digest = sha256_digest(canonical_json_bytes(history_projection))
    return (
        tuple(loaded),
        tuple(raw_documents),
        tuple(rings),
        history_digest,
    )


def _validate_nonce(value: str, path: str) -> None:
    decoded = _decode_base64url(value, _nonce_decoded_size(value, path), path)
    require(
        len(decoded) >= 16,
        "FRESHNESS_NONCE_INVALID",
        path,
        "nonce must contain at least 128 bits of fresh randomness",
    )


def _nonce_decoded_size(value: Any, path: str) -> int:
    require(
        isinstance(value, str) and value,
        "FRESHNESS_NONCE_INVALID",
        path,
        "an independently generated nonce is required",
    )
    try:
        decoded = base64.b64decode(
            value + "=" * ((-len(value)) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        fail("FRESHNESS_NONCE_INVALID", path, str(exc))
    return len(decoded)


def _validate_freshness(
    schemas: ContractSchemas,
    document: JsonDocument,
    *,
    verifier_nonce: str,
    now: datetime,
    anchor_kind: str,
    anchor: Mapping[str, Any],
    anchor_raw: bytes,
    anchor_schema_ref: str,
    subject_field: str,
    root_set: Mapping[str, Any],
    path: str,
) -> tuple[dict[str, Any], bytes, datetime]:
    envelope, raw = _document(document, path)
    schemas.validate("anchor_freshness", envelope, path)
    _validate_nonce(verifier_nonce, f"{path}.verifierNonce")
    _canonical_order(
        envelope["rootSignatures"], f"{path}.rootSignatures", key="rootKeyId"
    )

    expected = {
        "anchorKind": anchor_kind,
        "authorityId": anchor["authorityId"],
        "subjectId": anchor[subject_field],
        "anchorBlobSha256": sha256_digest(anchor_raw),
        "anchorSchemaRef": anchor_schema_ref,
        "anchorSchemaSha256": _schema_hash(
            schemas, anchor_schema_ref, f"{path}.anchorSchemaSha256"
        ),
        "anchorDigest": anchor["anchorDigest"],
        "anchorVersion": anchor["anchorVersion"],
        "resourceVersion": anchor["resourceVersion"],
        "verifierNonce": verifier_nonce,
        "trustRootDigest": root_set["rootSetDigest"],
    }
    for name, value in expected.items():
        require(
            envelope.get(name) == value,
            "ANCHOR_FRESHNESS_BINDING_MISMATCH",
            f"{path}.{name}",
            f"expected live-anchor binding {value!r}, got {envelope.get(name)!r}",
        )

    observed = _timestamp(envelope["observedAt"], f"{path}.observedAt")
    expires = _timestamp(envelope["expiresAt"], f"{path}.expiresAt")
    require(
        observed < expires,
        "ANCHOR_FRESHNESS_TIME_INVALID",
        path,
        "observedAt must precede expiresAt",
    )
    require(
        (expires - observed).total_seconds() <= 300,
        "ANCHOR_FRESHNESS_TIME_INVALID",
        path,
        "freshness lifetime exceeds 300 seconds",
    )
    require(
        observed <= now <= expires,
        "ANCHOR_FRESHNESS_EXPIRED",
        path,
        "freshness envelope is not live at evaluator time",
    )
    require(
        _timestamp(anchor["updatedAt"], f"{path}.anchor.updatedAt") <= observed,
        "ANCHOR_FRESHNESS_TIME_INVALID",
        f"{path}.observedAt",
        "observation predates the committed anchor update",
    )
    receipt = anchor.get("receipt")
    if isinstance(receipt, Mapping):
        require(
            _timestamp(receipt["issuedAt"], f"{path}.anchor.receipt.issuedAt")
            <= observed,
            "ANCHOR_FRESHNESS_TIME_INVALID",
            f"{path}.observedAt",
            "observation predates the committed anchor receipt",
        )
        for number, signature in enumerate(receipt["rootSignatures"]):
            require(
                _timestamp(
                    signature["signedAt"],
                    f"{path}.anchor.receipt.rootSignatures[{number}].signedAt",
                )
                <= observed,
                "ANCHOR_FRESHNESS_TIME_INVALID",
                f"{path}.observedAt",
                "observation predates completion of the anchor receipt quorum",
            )

    digest, _ = _projection_digest(
        envelope,
        null_fields=("freshnessReceiptDigest",),
        empty_array_fields=("rootSignatures",),
        path=f"{path}.digestProjection",
    )
    _require_digest(
        envelope["freshnessReceiptDigest"],
        digest,
        f"{path}.freshnessReceiptDigest",
        "ANCHOR_FRESHNESS_DIGEST_INVALID",
    )
    _verify_root_quorum(
        root_set,
        envelope["rootSignatures"],
        digest_field="freshnessReceiptDigest",
        digest=digest,
        domain=_FRESHNESS_DOMAIN,
        path=f"{path}.rootSignatures",
        require_algorithm=True,
        not_before=observed,
        not_after=min(
            expires,
            now + _MAX_FRESHNESS_SIGNATURE_FUTURE_SKEW,
        ),
    )
    return envelope, raw, expires


def _validate_trust_anchor(
    schemas: ContractSchemas,
    document: JsonDocument,
    *,
    rings: tuple[_VerifiedRing, ...],
) -> tuple[dict[str, Any], bytes]:
    path = "trust.externalTrustAnchor"
    anchor, raw = _document(document, path)
    schemas.validate("trust_anchor", anchor, path)
    digest, _ = _projection_digest(
        anchor, null_fields=("anchorDigest",), path=f"{path}.digestProjection"
    )
    _require_digest(
        anchor["anchorDigest"],
        digest,
        f"{path}.anchorDigest",
        "ROLLBACK_ANCHOR_DIGEST_INVALID",
    )
    require(
        anchor["anchorVersion"] == anchor["resourceVersion"],
        "ROLLBACK_ANCHOR_CAS_INVALID",
        path,
        "anchorVersion and resourceVersion must advance in lockstep",
    )
    cas = anchor["casPrecondition"]
    if anchor["anchorVersion"] == 1:
        require(
            anchor["resourceVersion"] == 1
            and anchor["previousAnchorDigestOrNull"] is None
            and all(value is None for value in cas.values()),
            "ROLLBACK_ANCHOR_CAS_INVALID",
            path,
            "genesis requires 1/1 versions, no predecessor, and null CAS state",
        )
    else:
        require(
            anchor["anchorVersion"] == cas["expectedAnchorVersionOrNull"] + 1,
            "ROLLBACK_ANCHOR_CAS_INVALID",
            f"{path}.anchorVersion",
            "successor must increment the CAS anchor version by one",
        )
        require(
            anchor["resourceVersion"] == cas["expectedResourceVersionOrNull"] + 1,
            "ROLLBACK_ANCHOR_CAS_INVALID",
            f"{path}.resourceVersion",
            "successor must increment the CAS resource version by one",
        )
        require(
            anchor["previousAnchorDigestOrNull"] == cas["expectedAnchorDigestOrNull"],
            "ROLLBACK_ANCHOR_CAS_INVALID",
            f"{path}.previousAnchorDigestOrNull",
            "successor does not bind the CAS predecessor digest",
        )
        expected_sequence = cas["expectedMinimumSequenceOrNull"]
        require(
            expected_sequence <= len(rings),
            "ROLLBACK_ANCHOR_CAS_INVALID",
            f"{path}.casPrecondition.expectedMinimumSequenceOrNull",
            "predecessor sequence is absent from verified key-ring history",
        )
        require(
            cas["expectedAcceptedKeyRingDigestOrNull"]
            == rings[expected_sequence - 1].digest,
            "ROLLBACK_ANCHOR_CAS_INVALID",
            f"{path}.casPrecondition.expectedAcceptedKeyRingDigestOrNull",
            "predecessor digest does not resolve in verified key-ring history",
        )
        require(
            anchor["minimumSequence"] >= expected_sequence,
            "ROLLBACK_DETECTED",
            f"{path}.minimumSequence",
            "accepted key-ring sequence decreased",
        )
        if anchor["minimumSequence"] == expected_sequence:
            require(
                anchor["acceptedKeyRingDigest"]
                == cas["expectedAcceptedKeyRingDigestOrNull"],
                "ROLLBACK_ANCHOR_EQUIVOCATION",
                f"{path}.acceptedKeyRingDigest",
                "same sequence has a different accepted digest",
            )

    current = rings[-1]
    require(
        anchor["keyRingId"] == current.key_ring_id,
        "ROLLBACK_ANCHOR_BINDING_MISMATCH",
        f"{path}.keyRingId",
        "anchor does not bind the authenticated key-ring history",
    )
    require(
        anchor["minimumSequence"] == current.sequence,
        "ROLLBACK_ANCHOR_BINDING_MISMATCH",
        f"{path}.minimumSequence",
        "anchor must accept the exact current ring sequence",
    )
    require(
        anchor["acceptedKeyRingDigest"] == current.digest,
        "ROLLBACK_ANCHOR_BINDING_MISMATCH",
        f"{path}.acceptedKeyRingDigest",
        "anchor must accept the exact current ring digest",
    )
    return anchor, raw


def verify_trust_context(
    schemas: ContractSchemas,
    *,
    pinned_root_set: JsonDocument,
    pinned_root_digest: str,
    key_ring_documents: Sequence[JsonDocument],
    external_trust_anchor: JsonDocument,
    trust_anchor_freshness: JsonDocument,
    verifier_nonce: str,
    now: datetime,
) -> VerifiedTrustContext:
    """Verify the complete trust bootstrap without performing external writes.

    ``pinned_root_digest``, ``external_trust_anchor``,
    ``trust_anchor_freshness``, ``verifier_nonce``, and ``now`` are independent
    verifier inputs.  The target repository or an evidence bundle must not
    select them.  The current anchor's embedded CAS predecessor fields receive
    structural consistency checks only: proving predecessor bytes,
    linearizable current-record reads, and atomic CAS success remains the
    external authority adapter's product responsibility.
    """

    verified_now = _utc_now(now)
    root_set, _ = _validate_root_set(schemas, pinned_root_set, pinned_root_digest)
    _, _, rings, history_digest = _validate_ring_history(
        schemas, key_ring_documents, root_set, verified_now
    )
    anchor, anchor_raw = _validate_trust_anchor(
        schemas, external_trust_anchor, rings=rings
    )
    freshness, _, freshness_expires = _validate_freshness(
        schemas,
        trust_anchor_freshness,
        verifier_nonce=verifier_nonce,
        now=verified_now,
        anchor_kind="TRUST_KEY_RING",
        anchor=anchor,
        anchor_raw=anchor_raw,
        anchor_schema_ref=_TRUST_ANCHOR_SCHEMA,
        subject_field="keyRingId",
        root_set=root_set,
        path="trust.trustAnchorFreshness",
    )

    current = rings[-1]
    context_projection = {
        "profileVersion": 1,
        "rootSetDigest": root_set["rootSetDigest"],
        "verifiedHistoryDigest": history_digest,
        "keyRingId": current.key_ring_id,
        "keyRingSequence": current.sequence,
        "keyRingDigest": current.digest,
        "trustAnchorDigest": anchor["anchorDigest"],
        "trustAnchorVersion": anchor["anchorVersion"],
        "trustAnchorResourceVersion": anchor["resourceVersion"],
        "trustAnchorAuthorityId": anchor["authorityId"],
    }
    context_digest = sha256_digest(canonical_json_bytes(context_projection))
    return VerifiedTrustContext._construct(
        root_set_id=root_set["rootSetId"],
        root_set_digest=root_set["rootSetDigest"],
        key_ring_id=current.key_ring_id,
        key_ring_sequence=current.sequence,
        key_ring_digest=current.digest,
        verified_history_digest=history_digest,
        trust_anchor_digest=anchor["anchorDigest"],
        trust_anchor_version=anchor["anchorVersion"],
        trust_anchor_resource_version=anchor["resourceVersion"],
        trust_anchor_authority_id=anchor["authorityId"],
        freshness_receipt_digest=freshness["freshnessReceiptDigest"],
        freshness_anchor_path=freshness["anchorPath"],
        freshness_expires_at=freshness_expires,
        verified_at=verified_now,
        context_digest=context_digest,
        keys=current.keys,
        _root_set=_deep_freeze(root_set),
        _rings=rings,
    )


def _ring_for_version(
    trust: VerifiedTrustContext, value: Any, path: str
) -> _VerifiedRing:
    require_factory_verified(
        trust,
        VerifiedTrustContext,
        code="TRUST_CONTEXT_INVALID",
        path="trust",
        message="trust context must come from verify_trust_context",
    )
    require(
        isinstance(value, int) and not isinstance(value, bool),
        "KEY_RING_VERSION_INVALID",
        path,
        "expected a key-ring sequence",
    )
    require(
        1 <= value <= len(trust._rings),
        "KEY_RING_VERSION_INVALID",
        path,
        "referenced key-ring sequence is absent from authenticated history",
    )
    ring = trust._rings[value - 1]
    require(
        ring.sequence == value,
        "KEY_RING_VERSION_INVALID",
        path,
        "authenticated history sequence mismatch",
    )
    return ring


def _verify_role_signed_document(
    document: Mapping[str, Any],
    *,
    trust: VerifiedTrustContext,
    digest_field: str,
    signature_field: str,
    signer_field: str,
    signed_time_field: str,
    domain: bytes,
    required_role: str,
    path: str,
    require_current_ring: bool,
    evaluation_time: datetime,
) -> tuple[str, VerifiedKey]:
    digest, projection_raw = _projection_digest(
        document,
        null_fields=(digest_field, signature_field),
        path=f"{path}.digestProjection",
    )
    _require_digest(
        document.get(digest_field),
        digest,
        f"{path}.{digest_field}",
        "SIGNED_DOCUMENT_DIGEST_INVALID",
    )
    ring = _ring_for_version(
        trust, document.get("keyRingVersion"), f"{path}.keyRingVersion"
    )
    if require_current_ring:
        require(
            ring.sequence == trust.key_ring_sequence,
            "STALE_SIGNING_AUTHORITY",
            f"{path}.keyRingVersion",
            "current release content must use the authenticated current ring",
        )
    key_id = document.get(signer_field)
    require(
        isinstance(key_id, str) and key_id in ring.keys,
        "SIGNER_UNKNOWN",
        f"{path}.{signer_field}",
        f"signer {key_id!r} is absent from key-ring sequence {ring.sequence}",
    )
    key = ring.keys[key_id]
    require(
        required_role in key.roles,
        "SIGNER_ROLE_INVALID",
        f"{path}.{signer_field}",
        f"signer lacks required role {required_role}",
    )
    signed_at = _timestamp(
        document.get(signed_time_field), f"{path}.{signed_time_field}"
    )
    require(
        ring.not_before <= signed_at < ring.expires_at,
        "SIGNER_INACTIVE",
        path,
        "key ring was not active at signed time",
    )
    require(
        key.not_before <= signed_at < key.not_after,
        "SIGNER_INACTIVE",
        path,
        "signer key was not active at signed time",
    )
    require(
        key_id not in ring.revoked_key_ids,
        "SIGNER_REVOKED",
        f"{path}.{signer_field}",
        "signer is in the authenticated ring revocation set",
    )
    if key.revoked_at is not None:
        require(
            signed_at < key.revoked_at,
            "SIGNER_REVOKED",
            path,
            "signer was revoked at signed time",
        )
    if require_current_ring:
        require(
            key.not_before <= evaluation_time < key.not_after,
            "STALE_SIGNING_AUTHORITY",
            f"{path}.{signer_field}",
            "current release signer is not active at evaluator time",
        )
        if key.revoked_at is not None:
            require(
                evaluation_time < key.revoked_at,
                "SIGNER_REVOKED",
                f"{path}.{signer_field}",
                "current release signer is revoked at evaluator time",
            )
    _verify_ed25519(
        key.public_key_base64url,
        document.get(signature_field),
        domain + projection_raw,
        path,
    )
    return digest, key


def _validate_catalog_history(
    schemas: ContractSchemas,
    trust: VerifiedTrustContext,
    documents: Sequence[JsonDocument],
    now: datetime,
) -> tuple[
    tuple[dict[str, Any], ...],
    tuple[bytes, ...],
    tuple[str, ...],
    VerifiedKey,
]:
    require(
        isinstance(documents, Sequence)
        and not isinstance(documents, (str, bytes, bytearray, memoryview))
        and len(documents) > 0,
        "CATALOG_CHAIN_INCOMPLETE",
        "qualification.catalogDocuments",
        "the complete non-empty catalog sequence 1..current is required",
    )
    loaded: list[dict[str, Any]] = []
    raw_documents: list[bytes] = []
    digests: list[str] = []
    product_signers: list[VerifiedKey] = []
    catalog_id: str | None = None
    previous_digest: str | None = None
    previous_issued: datetime | None = None

    for index, value in enumerate(documents):
        path = f"qualification.catalogDocuments[{index}]"
        catalog, raw = _document(value, path)
        schemas.validate("catalog", catalog, path)
        _canonical_order(
            catalog["qualificationRecordDigests"],
            f"{path}.qualificationRecordDigests",
        )
        _canonical_order(
            catalog["denyAndRevocationEntries"],
            f"{path}.denyAndRevocationEntries",
            key="entryId",
        )
        for number, entry in enumerate(catalog["denyAndRevocationEntries"]):
            _timestamp(
                entry["effectiveAt"],
                f"{path}.denyAndRevocationEntries[{number}].effectiveAt",
            )

        expected_sequence = index + 1
        require(
            catalog["catalogSequence"] == expected_sequence,
            "CATALOG_CHAIN_GAP",
            f"{path}.catalogSequence",
            f"expected exact sequence {expected_sequence}",
        )
        if catalog_id is None:
            catalog_id = catalog["catalogId"]
        require(
            catalog["catalogId"] == catalog_id,
            "CATALOG_CHAIN_FORK",
            f"{path}.catalogId",
            "catalogId changed inside one chain",
        )
        require(
            catalog["previousCatalogDigest"] == previous_digest,
            "CATALOG_CHAIN_FORK",
            f"{path}.previousCatalogDigest",
            f"expected {previous_digest!r}",
        )

        issued = _timestamp(catalog["issuedAt"], f"{path}.issuedAt")
        not_before = _timestamp(catalog["notBefore"], f"{path}.notBefore")
        expires = _timestamp(catalog["expiresAt"], f"{path}.expiresAt")
        require(
            issued <= not_before < expires,
            "CATALOG_TIME_INVALID",
            path,
            "required ordering is issuedAt <= notBefore < expiresAt",
        )
        require(
            issued <= now,
            "CATALOG_TIME_INVALID",
            f"{path}.issuedAt",
            "catalog issuance is future-dated",
        )
        if previous_issued is not None:
            require(
                issued >= previous_issued,
                "CATALOG_CHAIN_FORK",
                f"{path}.issuedAt",
                "catalog issuance time precedes its verified predecessor",
            )
        previous_issued = issued
        is_current = index == len(documents) - 1
        if is_current:
            require(
                not_before <= now < expires,
                "CATALOG_NOT_CURRENT",
                path,
                "current catalog is outside its validity interval",
            )
        digest, signer = _verify_role_signed_document(
            catalog,
            trust=trust,
            digest_field="catalogDigest",
            signature_field="signature",
            signer_field="productReleaseSignerKeyId",
            signed_time_field="issuedAt",
            domain=_CATALOG_DOMAIN,
            required_role="PRODUCT_RELEASE",
            path=path,
            require_current_ring=is_current,
            evaluation_time=now,
        )
        require(
            digest not in digests,
            "CATALOG_CHAIN_FORK",
            f"{path}.catalogDigest",
            "catalog digest is reused at another sequence",
        )
        previous_digest = digest
        digests.append(digest)
        loaded.append(catalog)
        raw_documents.append(raw)
        product_signers.append(signer)

    return (
        tuple(loaded),
        tuple(raw_documents),
        tuple(digests),
        product_signers[-1],
    )


def _validate_catalog_anchor_receipt(
    anchor: Mapping[str, Any],
    root_set: Mapping[str, Any],
    path: str,
) -> None:
    receipt = anchor["receipt"]
    bindings = {
        "subjectAnchorDigest": anchor["anchorDigest"],
        "catalogId": anchor["catalogId"],
        "minimumCatalogSequence": anchor["minimumCatalogSequence"],
        "acceptedCatalogDigest": anchor["acceptedCatalogDigest"],
        "anchorVersion": anchor["anchorVersion"],
        "resourceVersion": anchor["resourceVersion"],
        "authorityId": anchor["authorityId"],
        "trustRootDigest": root_set["rootSetDigest"],
    }
    for name, expected in bindings.items():
        require(
            receipt.get(name) == expected,
            "CATALOG_ANCHOR_RECEIPT_BINDING_MISMATCH",
            f"{path}.receipt.{name}",
            f"receipt does not bind top-level value {expected!r}",
        )
    issued = _timestamp(receipt["issuedAt"], f"{path}.receipt.issuedAt")
    updated = _timestamp(anchor["updatedAt"], f"{path}.updatedAt")
    require(
        issued >= updated,
        "CATALOG_ANCHOR_RECEIPT_TIME_INVALID",
        f"{path}.receipt.issuedAt",
        "receipt predates the committed anchor update",
    )
    _canonical_order(
        receipt["rootSignatures"],
        f"{path}.receipt.rootSignatures",
        key="rootKeyId",
    )
    digest, _ = _projection_digest(
        receipt,
        null_fields=("receiptDigest",),
        empty_array_fields=("rootSignatures",),
        path=f"{path}.receipt.digestProjection",
    )
    _require_digest(
        receipt["receiptDigest"],
        digest,
        f"{path}.receipt.receiptDigest",
        "CATALOG_ANCHOR_RECEIPT_DIGEST_INVALID",
    )
    _verify_root_quorum(
        root_set,
        receipt["rootSignatures"],
        digest_field="receiptDigest",
        digest=digest,
        domain=_CATALOG_RECEIPT_DOMAIN,
        path=f"{path}.receipt.rootSignatures",
        require_algorithm=True,
        not_before=issued,
    )


def _validate_catalog_anchor(
    schemas: ContractSchemas,
    document: JsonDocument,
    *,
    catalogs: tuple[dict[str, Any], ...],
    catalog_digests: tuple[str, ...],
    root_set: Mapping[str, Any],
) -> tuple[dict[str, Any], bytes]:
    path = "qualification.externalCatalogAnchor"
    anchor, raw = _document(document, path)
    schemas.validate("catalog_anchor", anchor, path)
    require(
        anchor["recordState"] == "COMMITTED",
        "CATALOG_ANCHOR_NOT_COMMITTED",
        f"{path}.recordState",
        "only a committed external catalog anchor is authoritative",
    )
    digest, _ = _projection_digest(
        anchor,
        null_fields=("anchorDigest", "receipt"),
        path=f"{path}.digestProjection",
    )
    _require_digest(
        anchor["anchorDigest"],
        digest,
        f"{path}.anchorDigest",
        "CATALOG_ANCHOR_DIGEST_INVALID",
    )
    require(
        anchor["anchorVersion"] == anchor["resourceVersion"],
        "CATALOG_ANCHOR_CAS_INVALID",
        path,
        "anchorVersion and resourceVersion must advance in lockstep",
    )
    cas = anchor["casPrecondition"]
    if anchor["anchorVersion"] == 1:
        require(
            anchor["resourceVersion"] == 1
            and anchor["previousAnchorDigestOrNull"] is None
            and all(value is None for value in cas.values()),
            "CATALOG_ANCHOR_CAS_INVALID",
            path,
            "genesis requires 1/1 versions, no predecessor, and null CAS state",
        )
    else:
        require(
            anchor["anchorVersion"] == cas["expectedAnchorVersionOrNull"] + 1,
            "CATALOG_ANCHOR_CAS_INVALID",
            f"{path}.anchorVersion",
            "successor must increment CAS anchor version by one",
        )
        require(
            anchor["resourceVersion"] == cas["expectedResourceVersionOrNull"] + 1,
            "CATALOG_ANCHOR_CAS_INVALID",
            f"{path}.resourceVersion",
            "successor must increment CAS resource version by one",
        )
        require(
            anchor["previousAnchorDigestOrNull"] == cas["expectedAnchorDigestOrNull"],
            "CATALOG_ANCHOR_CAS_INVALID",
            f"{path}.previousAnchorDigestOrNull",
            "successor does not bind the CAS predecessor digest",
        )
        expected_sequence = cas["expectedMinimumCatalogSequenceOrNull"]
        require(
            expected_sequence <= len(catalogs),
            "CATALOG_ANCHOR_CAS_INVALID",
            f"{path}.casPrecondition.expectedMinimumCatalogSequenceOrNull",
            "predecessor sequence is absent from verified catalog history",
        )
        require(
            cas["expectedAcceptedCatalogDigestOrNull"]
            == catalog_digests[expected_sequence - 1],
            "CATALOG_ANCHOR_CAS_INVALID",
            f"{path}.casPrecondition.expectedAcceptedCatalogDigestOrNull",
            "predecessor digest does not resolve in verified catalog history",
        )
        require(
            anchor["minimumCatalogSequence"] >= expected_sequence,
            "CATALOG_ROLLBACK_DETECTED",
            f"{path}.minimumCatalogSequence",
            "accepted catalog sequence decreased",
        )
        if anchor["minimumCatalogSequence"] == expected_sequence:
            require(
                anchor["acceptedCatalogDigest"]
                == cas["expectedAcceptedCatalogDigestOrNull"],
                "CATALOG_ANCHOR_EQUIVOCATION",
                f"{path}.acceptedCatalogDigest",
                "same sequence has a different accepted digest",
            )
        else:
            require(
                anchor["minimumCatalogSequence"] == expected_sequence + 1,
                "CATALOG_CHAIN_GAP",
                f"{path}.minimumCatalogSequence",
                "catalog anchor advancement cannot skip a predecessor",
            )
            require(
                catalogs[-1]["previousCatalogDigest"]
                == cas["expectedAcceptedCatalogDigestOrNull"],
                "CATALOG_CHAIN_FORK",
                f"{path}.casPrecondition.expectedAcceptedCatalogDigestOrNull",
                "current catalog does not extend the CAS-accepted predecessor",
            )

    current = catalogs[-1]
    require(
        anchor["catalogId"] == current["catalogId"],
        "CATALOG_ANCHOR_BINDING_MISMATCH",
        f"{path}.catalogId",
        "anchor does not bind the current catalog ID",
    )
    require(
        anchor["minimumCatalogSequence"] == current["catalogSequence"],
        "CATALOG_ANCHOR_BINDING_MISMATCH",
        f"{path}.minimumCatalogSequence",
        "anchor must accept the exact current catalog sequence",
    )
    require(
        anchor["acceptedCatalogDigest"] == current["catalogDigest"],
        "CATALOG_ANCHOR_BINDING_MISMATCH",
        f"{path}.acceptedCatalogDigest",
        "anchor must accept the exact current catalog digest",
    )
    _validate_catalog_anchor_receipt(anchor, root_set, path)
    return anchor, raw


def _qualification_selectors(
    record: Mapping[str, Any], path: str
) -> tuple[tuple[str, str], ...]:
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
    try:
        return tuple(
            sorted(
                selectors,
                key=lambda item: canonical_json_bytes(
                    {"selectorKind": item[0], "selectorDigest": item[1]}
                ),
            )
        )
    except (CanonicalizationError, TypeError, ValueError) as exc:
        fail("CANONICAL_JSON_INVALID", path, str(exc))


def _validate_qualification_record(
    schemas: ContractSchemas,
    trust: VerifiedTrustContext,
    document: JsonDocument,
    *,
    index: int,
    now: datetime,
) -> tuple[dict[str, Any], bytes, str, VerifiedKey]:
    path = f"qualification.records[{index}]"
    record, raw = _document(document, path)
    schemas.validate("qualification_record", record, path)
    for name in ("deviceTraits", "caseIds", "e4EvidenceHashes"):
        _canonical_order(record[name], f"{path}.{name}")
    _canonical_order(
        record["kernelQemuFirmwareBackend"]["runtimeCapabilities"],
        f"{path}.kernelQemuFirmwareBackend.runtimeCapabilities",
    )
    _canonical_order(
        record["guestDriverAndWorkload"]["guestCapabilities"],
        f"{path}.guestDriverAndWorkload.guestCapabilities",
    )

    exact_projection = {
        name: copy.deepcopy(record[name])
        for name in (
            "platformProfileHash",
            "pciIdentityMatch",
            "deviceArchetype",
            "qualificationCaseMatrixSha256",
            "deviceFirmwareAndRom",
            "kernelQemuFirmwareBackend",
            "iommuInterruptResetProviders",
            "guestDriverAndWorkload",
            "deviceTraits",
        )
    }
    exact_digest = sha256_digest(canonical_json_bytes(exact_projection))
    _require_digest(
        record["exactQualificationKey"],
        exact_digest,
        f"{path}.exactQualificationKey",
        "EXACT_QUALIFICATION_KEY_INVALID",
    )

    issued = _timestamp(record["issuedAt"], f"{path}.issuedAt")
    not_before = _timestamp(record["notBefore"], f"{path}.notBefore")
    expires = _timestamp(record["expiresAt"], f"{path}.expiresAt")
    require(
        issued <= not_before < expires,
        "QUALIFICATION_RECORD_TIME_INVALID",
        path,
        "required ordering is issuedAt <= notBefore < expiresAt",
    )
    require(
        not_before <= now < expires,
        "QUALIFICATION_RECORD_NOT_CURRENT",
        path,
        "record is outside its validity interval",
    )
    digest, signer = _verify_role_signed_document(
        record,
        trust=trust,
        digest_field="recordDigest",
        signature_field="signature",
        signer_field="qualificationSignerKeyId",
        signed_time_field="issuedAt",
        domain=_QUALIFICATION_DOMAIN,
        required_role="QUALIFICATION_ENGINEERING",
        path=path,
        require_current_ring=True,
        evaluation_time=now,
    )
    return record, raw, digest, signer


def verify_qualification_context(
    schemas: ContractSchemas,
    trust: VerifiedTrustContext,
    *,
    catalog_documents: Sequence[JsonDocument],
    qualification_records: Sequence[JsonDocument],
    external_catalog_anchor: JsonDocument,
    catalog_anchor_freshness: JsonDocument,
    verifier_nonce: str,
    now: datetime,
) -> VerifiedQualificationContext:
    """Resolve the current signed catalog into immutable exact dependencies.

    This verifies catalog/record schema, signatures, complete catalog chains,
    exact current membership, external rollback acceptance, nonce freshness,
    signer separation, exact qualification-key derivation, and every supported
    deny selector.  It intentionally does not replace recursive E4 evidence or
    qualification-subject replay; the caller must construct records only after
    that separate evidence closure is verified.
    """

    require_factory_verified(
        trust,
        VerifiedTrustContext,
        code="TRUST_CONTEXT_INVALID",
        path="qualification.trust",
        message="trust context must come from verify_trust_context",
    )
    verified_now = _utc_now(now)
    require(
        trust.verified_at <= verified_now <= trust.freshness_expires_at,
        "TRUST_CONTEXT_STALE",
        "qualification.trust",
        "trust-anchor freshness is not live at qualification evaluation time",
    )
    current_ring = trust._rings[-1]
    require(
        current_ring.not_before <= verified_now < current_ring.expires_at,
        "KEY_RING_NOT_CURRENT",
        "qualification.trust",
        "authenticated current key ring is outside its validity interval",
    )

    (
        catalogs,
        catalog_raw_documents,
        catalog_digests,
        product_signer,
    ) = _validate_catalog_history(
        schemas,
        trust,
        catalog_documents,
        verified_now,
    )
    current_catalog = catalogs[-1]
    catalog_anchor, catalog_anchor_raw = _validate_catalog_anchor(
        schemas,
        external_catalog_anchor,
        catalogs=catalogs,
        catalog_digests=catalog_digests,
        root_set=trust._root_set,
    )
    freshness, _, freshness_expires = _validate_freshness(
        schemas,
        catalog_anchor_freshness,
        verifier_nonce=verifier_nonce,
        now=verified_now,
        anchor_kind="SUPPORTED_CATALOG",
        anchor=catalog_anchor,
        anchor_raw=catalog_anchor_raw,
        anchor_schema_ref=_CATALOG_ANCHOR_SCHEMA,
        subject_field="catalogId",
        root_set=trust._root_set,
        path="qualification.catalogAnchorFreshness",
    )

    require(
        isinstance(qualification_records, Sequence)
        and not isinstance(qualification_records, (str, bytes, bytearray, memoryview)),
        "QUALIFICATION_RECORD_SET_INVALID",
        "qualification.records",
        "expected the complete current catalog record sequence",
    )
    verified_records: list[tuple[dict[str, Any], bytes, str, VerifiedKey]] = []
    record_digests: set[str] = set()
    record_ids: set[str] = set()
    exact_keys: set[str] = set()
    for index, document in enumerate(qualification_records):
        record, raw, digest, signer = _validate_qualification_record(
            schemas, trust, document, index=index, now=verified_now
        )
        require(
            digest not in record_digests,
            "QUALIFICATION_RECORD_AMBIGUOUS",
            f"qualification.records[{index}].recordDigest",
            "duplicate record digest",
        )
        require(
            record["qualificationRecordId"] not in record_ids,
            "QUALIFICATION_RECORD_AMBIGUOUS",
            f"qualification.records[{index}].qualificationRecordId",
            "duplicate record ID",
        )
        require(
            record["exactQualificationKey"] not in exact_keys,
            "QUALIFICATION_RECORD_AMBIGUOUS",
            f"qualification.records[{index}].exactQualificationKey",
            "more than one current record resolves the same exact key",
        )
        require(
            signer.key_id != product_signer.key_id
            and signer.principal_id != product_signer.principal_id
            and signer.public_key_base64url != product_signer.public_key_base64url,
            "SEPARATION_OF_DUTIES_VIOLATION",
            f"qualification.records[{index}].qualificationSignerKeyId",
            (
                "Qualification Engineering and Product Release must use "
                "different key IDs, principals, and key material"
            ),
        )
        record_digests.add(digest)
        record_ids.add(record["qualificationRecordId"])
        exact_keys.add(record["exactQualificationKey"])
        verified_records.append((record, raw, digest, signer))

    catalog_members = set(current_catalog["qualificationRecordDigests"])
    require(
        record_digests == catalog_members,
        "CATALOG_MEMBERSHIP_INCOMPLETE",
        "qualification.records",
        (
            "provided record digests must exactly equal current catalog "
            f"membership; missing={sorted(catalog_members - record_digests)}, "
            f"extra={sorted(record_digests - catalog_members)}"
        ),
    )

    catalog_not_before = _timestamp(
        current_catalog["notBefore"], "qualification.currentCatalog.notBefore"
    )
    catalog_expires = _timestamp(
        current_catalog["expiresAt"], "qualification.currentCatalog.expiresAt"
    )
    profiles: list[QualificationProfileDependency] = []
    deny_entries = current_catalog["denyAndRevocationEntries"]
    for index, (record, raw, digest, signer) in enumerate(verified_records):
        path = f"qualification.records[{index}]"
        selectors = _qualification_selectors(record, path)
        selector_set = set(selectors)
        applicable: list[tuple[str, datetime]] = []
        for deny_number, entry in enumerate(deny_entries):
            selector = (entry["selectorKind"], entry["selectorDigest"])
            if selector not in selector_set:
                continue
            entry_digest = sha256_digest(canonical_json_bytes(entry))
            effective_at = _timestamp(
                entry["effectiveAt"],
                (
                    "qualification.currentCatalog.denyAndRevocationEntries"
                    f"[{deny_number}].effectiveAt"
                ),
            )
            applicable.append((entry_digest, effective_at))
            require(
                effective_at > verified_now,
                "QUALIFICATION_DENIED",
                (
                    "qualification.currentCatalog.denyAndRevocationEntries"
                    f"[{deny_number}]"
                ),
                (
                    f"active {entry['selectorKind']} selector denies "
                    f"record {record['qualificationRecordId']!r}; "
                    f"reason={entry['reasonCode']!r}, "
                    f"behavior={entry['revocationBehavior']!r}"
                ),
            )
        applicable_digests = tuple(sorted(item[0] for item in applicable))
        record_not_before = _timestamp(record["notBefore"], f"{path}.notBefore")
        record_expires = _timestamp(record["expiresAt"], f"{path}.expiresAt")

        dependency_projection = {
            "profileVersion": 1,
            "rootSetDigest": trust.root_set_digest,
            "keyRingDigest": trust.key_ring_digest,
            "catalogAuthority": {
                "catalogId": current_catalog["catalogId"],
                "revocationBehavior": current_catalog["revocationBehavior"],
                "notBefore": current_catalog["notBefore"],
                "expiresAt": current_catalog["expiresAt"],
                "productReleaseSignerKeyId": product_signer.key_id,
                "productReleaseSignerPrincipalId": product_signer.principal_id,
                "catalogAnchorAuthorityId": catalog_anchor["authorityId"],
            },
            "qualificationRecordDigest": digest,
            "exactQualificationKey": record["exactQualificationKey"],
            "qualificationSignerKeyId": signer.key_id,
            "qualificationSignerPrincipalId": signer.principal_id,
            "selectors": [
                {"selectorKind": kind, "selectorDigest": value}
                for kind, value in selectors
            ],
            "applicableDenyEntryDigests": list(applicable_digests),
        }
        dependency_digest = sha256_digest(canonical_json_bytes(dependency_projection))
        validity_horizon = [
            record_expires,
            catalog_expires,
            current_ring.expires_at,
            trust.freshness_expires_at,
            freshness_expires,
            signer.not_after,
            product_signer.not_after,
        ]
        validity_horizon.extend(item[1] for item in applicable)
        if signer.revoked_at is not None:
            validity_horizon.append(signer.revoked_at)
        if product_signer.revoked_at is not None:
            validity_horizon.append(product_signer.revoked_at)
        profiles.append(
            QualificationProfileDependency._construct(
                qualification_record_id=record["qualificationRecordId"],
                qualification_record_digest=digest,
                qualification_record_canonical_digest=sha256_digest(raw),
                exact_qualification_key=record["exactQualificationKey"],
                platform_profile_hash=record["platformProfileHash"],
                qualification_signer_key_id=signer.key_id,
                qualification_signer_principal_id=signer.principal_id,
                selector_digests=selectors,
                applicable_deny_entry_digests=applicable_digests,
                not_before=max(
                    record_not_before,
                    catalog_not_before,
                    current_ring.not_before,
                    signer.not_before,
                    product_signer.not_before,
                ),
                expires_at=min(validity_horizon),
                dependency_digest=dependency_digest,
            )
        )

    profiles.sort(key=lambda item: canonical_json_bytes(item.exact_qualification_key))
    by_exact_key = MappingProxyType(
        {profile.exact_qualification_key: profile for profile in profiles}
    )
    context_projection = {
        "profileVersion": 1,
        "trustContextDigest": trust.context_digest,
        "catalogId": current_catalog["catalogId"],
        "catalogSequence": current_catalog["catalogSequence"],
        "catalogDigest": current_catalog["catalogDigest"],
        "catalogAnchorDigest": catalog_anchor["anchorDigest"],
        "catalogAnchorVersion": catalog_anchor["anchorVersion"],
        "catalogAnchorResourceVersion": catalog_anchor["resourceVersion"],
        "catalogAnchorAuthorityId": catalog_anchor["authorityId"],
        "qualificationRecordDigests": sorted(record_digests),
    }
    context_digest = sha256_digest(canonical_json_bytes(context_projection))
    return VerifiedQualificationContext._construct(
        trust=trust,
        catalog_id=current_catalog["catalogId"],
        catalog_sequence=current_catalog["catalogSequence"],
        catalog_digest=current_catalog["catalogDigest"],
        catalog_canonical_digest=sha256_digest(catalog_raw_documents[-1]),
        product_release_signer_key_id=product_signer.key_id,
        product_release_signer_principal_id=product_signer.principal_id,
        catalog_anchor_digest=catalog_anchor["anchorDigest"],
        catalog_anchor_version=catalog_anchor["anchorVersion"],
        catalog_anchor_resource_version=catalog_anchor["resourceVersion"],
        catalog_anchor_authority_id=catalog_anchor["authorityId"],
        catalog_anchor_receipt_digest=(catalog_anchor["receipt"]["receiptDigest"]),
        freshness_receipt_digest=freshness["freshnessReceiptDigest"],
        freshness_verifier_nonce=freshness["verifierNonce"],
        freshness_observed_at=_timestamp(
            freshness["observedAt"],
            "qualification.catalogAnchorFreshness.observedAt",
        ),
        freshness_expires_at=freshness_expires,
        verified_at=verified_now,
        context_digest=context_digest,
        profiles=tuple(profiles),
        profiles_by_exact_key=by_exact_key,
    )


__all__ = [
    "JsonDocument",
    "QualificationProfileDependency",
    "VerifiedKey",
    "VerifiedQualificationContext",
    "VerifiedTrustContext",
    "verify_qualification_context",
    "verify_trust_context",
]
