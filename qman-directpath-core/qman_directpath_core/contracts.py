"""Schema validation against the authoritative portable contract directory."""

from __future__ import annotations

import json
from pathlib import Path
from types import MappingProxyType
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker, validators
from jsonschema.exceptions import ValidationError
from referencing import Registry, Resource

from .canonical import (
    CanonicalizationError,
    canonical_json_bytes,
    sha256_digest,
)
from .errors import fail


SCHEMA_FILES = {
    "root_set": "directpath-trust-root-set.schema.json",
    "key_ring": "directpath-trust-key-ring.schema.json",
    "key_ring_history": "directpath-trust-key-ring-history.schema.json",
    "trust_anchor": "directpath-trust-rollback-anchor.schema.json",
    "anchor_freshness": "directpath-anchor-freshness-envelope.schema.json",
    "host_snapshot_anchor": (
        "directpath-host-snapshot-rollback-anchor.schema.json"
    ),
    "host_snapshot_publication_trace": (
        "directpath-host-snapshot-publication-trace.schema.json"
    ),
    "catalog": "directpath-supported-catalog.schema.json",
    "catalog_anchor": "directpath-catalog-rollback-anchor.schema.json",
    "qualification_record": "directpath-qualification-record.schema.json",
    "qualification_profile_projection": (
        "directpath-qualification-profile-projection.schema.json"
    ),
    "qualification_verification_receipt": (
        "directpath-qualification-verification-receipt.schema.json"
    ),
    "identity": "directpath-identity-v1.schema.json",
    "portable_hash_subjects": ("directpath-portable-hash-subjects.schema.json"),
    "portable_entities": "directpath-portable-entities.schema.json",
    "authority_entities": "directpath-authority-entities.schema.json",
    "inventory_verification_receipt": (
        "directpath-inventory-verification-receipt.schema.json"
    ),
    "inventory_verifier_algorithm": (
        "directpath-inventory-verifier-algorithm.schema.json"
    ),
    "dependency_closure_request": ("directpath-dependency-closure-request.schema.json"),
    "reset_contract_set": "directpath-reset-contract-set.schema.json",
    "capability_policy": "directpath-capability-policy.schema.json",
    "operation_admission_binding": (
        "directpath-operation-admission-binding.schema.json"
    ),
}

QUERY_TRACE_SCHEMA_FILES = {
    "operation_payload": "directpath-operation-payload.schema.json",
    "query_read_trace": "directpath-query-read-trace.schema.json",
}

OPERATION_EXCHANGE_SCHEMA_FILES = {
    "operation_envelope": "directpath-operation-envelope.schema.json",
    "operation_payload": "directpath-operation-payload.schema.json",
    "host_snapshot_publication_repository_receipt": (
        "directpath-host-snapshot-publication-repository-receipt.schema.json"
    ),
}


def _linear_unique_items(
    _validator: object,
    unique_items: object,
    instance: object,
    _schema: object,
):
    """Validate canonical JSON arrays in O(total retained item bytes)."""

    if unique_items is not True or not isinstance(instance, list):
        return
    seen: set[bytes] = set()
    for item in instance:
        try:
            identity = canonical_json_bytes(item)
        except (CanonicalizationError, RecursionError, TypeError, ValueError):
            # Another schema/type/canonical-input check owns this failure.
            return
        if identity in seen:
            yield ValidationError("array items are not unique")
            return
        seen.add(identity)


_ClosedDraft202012Validator = validators.extend(
    Draft202012Validator,
    validators={"uniqueItems": _linear_unique_items},
)


class ContractSchemas:
    """Loaded, immutable schema registry selected by deployment configuration."""

    def __init__(
        self,
        contract_directory: str | Path,
        *,
        include_query_read_trace: bool = False,
        include_operation_exchange: bool = False,
    ):
        self.directory = Path(contract_directory).resolve()
        schemas: dict[str, dict[str, Any]] = {}
        schema_digests_by_ref: dict[str, str] = {}
        schema_ids_by_ref: dict[str, str] = {}
        registry = Registry()
        selected_schema_files = dict(SCHEMA_FILES)
        if include_query_read_trace:
            selected_schema_files.update(QUERY_TRACE_SCHEMA_FILES)
        if include_operation_exchange:
            selected_schema_files.update(OPERATION_EXCHANGE_SCHEMA_FILES)
        for kind, filename in selected_schema_files.items():
            path = self.directory / filename
            try:
                raw = path.read_bytes()
                schema = json.loads(raw)
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                fail(
                    "CONTRACT_SCHEMA_UNAVAILABLE",
                    f"contracts.{kind}",
                    f"cannot load {path}: {exc}",
                )
            try:
                Draft202012Validator.check_schema(schema)
                resource = Resource.from_contents(schema)
                schema_id = schema["$id"]
            except (KeyError, TypeError, ValueError) as exc:
                fail(
                    "CONTRACT_SCHEMA_INVALID",
                    f"contracts.{kind}",
                    f"{path} is not a closed Draft 2020-12 schema: {exc}",
                )
            registry = registry.with_resource(schema_id, resource)
            schemas[kind] = schema
            repository_ref = f"contracts/{filename}"
            schema_digests_by_ref[repository_ref] = sha256_digest(raw)
            schema_ids_by_ref[repository_ref] = schema_id
        self._schemas = MappingProxyType(schemas)
        self._schema_digests_by_ref = MappingProxyType(schema_digests_by_ref)
        self._schema_ids_by_ref = MappingProxyType(schema_ids_by_ref)
        self._registry = registry
        self._format_checker = FormatChecker()

    def digest_for_ref(self, schema_ref: str, *, path: str) -> str:
        """Return the digest of the exact schema bytes loaded for validation."""

        try:
            return self._schema_digests_by_ref[schema_ref]
        except (KeyError, TypeError):
            fail(
                "CONTRACT_SCHEMA_UNKNOWN",
                path,
                f"no loaded schema bytes are registered for {schema_ref!r}",
            )

    def validate(self, kind: str, instance: Any, path: str) -> None:
        try:
            schema = self._schemas[kind]
        except KeyError:
            fail(
                "CONTRACT_SCHEMA_UNKNOWN",
                path,
                f"no schema is registered for {kind!r}",
            )
        validator = _ClosedDraft202012Validator(
            schema,
            registry=self._registry,
            format_checker=self._format_checker,
        )
        error = next(validator.iter_errors(instance), None)
        if error is not None:
            suffix = "".join(
                f"[{item}]" if isinstance(item, int) else f".{item}"
                for item in error.absolute_path
            )
            fail(
                "CONTRACT_SCHEMA_VIOLATION",
                path + suffix,
                error.message,
            )

    def validate_ref(self, schema_ref: str, instance: Any, path: str) -> None:
        """Validate against one exact loaded file or JSON-Pointer fragment."""

        file_ref, separator, fragment = schema_ref.partition("#")
        try:
            schema_id = self._schema_ids_by_ref[file_ref]
        except (KeyError, TypeError):
            fail(
                "CONTRACT_SCHEMA_UNKNOWN",
                path,
                f"no loaded schema bytes are registered for {schema_ref!r}",
            )
        target = schema_id + ("#" + fragment if separator else "")
        validator = _ClosedDraft202012Validator(
            {"$ref": target},
            registry=self._registry,
            format_checker=self._format_checker,
        )
        error = next(validator.iter_errors(instance), None)
        if error is not None:
            suffix = "".join(
                f"[{item}]" if isinstance(item, int) else f".{item}"
                for item in error.absolute_path
            )
            fail(
                "CONTRACT_SCHEMA_VIOLATION",
                path + suffix,
                error.message,
            )
