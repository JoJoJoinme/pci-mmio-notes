#!/usr/bin/env python3
"""Fail-closed semantic validator for the portable DirectPath handoff.

JSON Schema checks document shape, but cannot prove that a target symbol, git
blob, signature, execution record, or qualification artifact is real.  This
module deliberately performs those cross-document and repository checks.  It
uses only the Python standard library; Ed25519 verification uses
``cryptography`` when a signed path is exercised and fails closed when that
package is unavailable.
"""

from __future__ import annotations

import argparse
import base64
import copy
import datetime as _datetime
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import unicodedata
from typing import Any, Iterable, Mapping, Sequence


SAFE_INTEGER = 9_007_199_254_740_991
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^(?:git:)?(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
SIGNATURE_RE = re.compile(r"^ed25519:[A-Za-z0-9_-]{86}$")
ZERO_DIGEST = "sha256:" + ("0" * 64)


# Executable artifacts supplied by C/E are untrusted input to this verifier.
# A deployment that wants to consume a final evaluator/classifier result must
# install an out-of-process isolation service here.  The callable itself and
# its attestation-verification policy are verifier configuration; neither can
# be selected by the target repository, mapping, evidence repository, or a
# signed artifact.  Keeping the default as ``None`` is intentional fail-closed
# behaviour for the portable baseline and for library callers.
_SIGNED_ARTIFACT_REPLAY_HOOK: Any | None = None


def configure_signed_artifact_replay_hook(hook: Any | None) -> None:
    """Install the verifier-owned signed-artifact isolation replay hook.

    The hook receives immutable ``bytes`` plus a closed metadata/request-digest
    projection.  It must run the artifact in an architecture-compatible
    sandbox, verify the returned isolation attestation using verifier-owned
    trust, and return the normalized response consumed below.  It must never
    delegate to an evidence-selected executable, command, PATH entry, or
    runner.  Passing ``None`` restores the fail-closed default.
    """

    if hook is not None and not callable(hook):
        raise TypeError("signed-artifact replay hook must be callable or None")
    global _SIGNED_ARTIFACT_REPLAY_HOOK
    _SIGNED_ARTIFACT_REPLAY_HOOK = hook


_SIGNED_ARTIFACT_REPLAY_PROTOCOL = (
    "QMAN-DIRECTPATH/SIGNED-ARTIFACT-REPLAY/V1"
)
_SIGNED_ARTIFACT_ATTESTATION_PROTOCOL = (
    "QMAN-DIRECTPATH/SIGNED-ARTIFACT-REPLAY-ATTESTATION/V1"
)
_SIGNED_ARTIFACT_REPLAY_POLICY = {
    "noNewPrivileges": True,
    "network": "DENY_ALL",
    "closureAccess": "DECLARED_CLOSURE_READ_ONLY",
    "inputAccess": "DECLARED_INPUTS_READ_ONLY",
    "outputAccess": "ONE_NEW_REGULAR_FILE_ONLY",
    "hostFilesystem": "DENY_ALL",
    "hostDevices": "DENY_ALL",
    "hostCredentials": "DENY_ALL",
    "childProcesses": "UNDECLARED_CHILDREN_DENIED",
    "limits": {
        "maximumProcessCount": 8,
        "maximumCpuMilliseconds": 60_000,
        "maximumMemoryBytes": 536_870_912,
        "maximumWrittenFileCount": 1,
        "maximumOutputBytes": 67_108_864,
        "maximumWallClockMilliseconds": 60_000,
    },
}


class DuplicateKeyError(ValueError):
    """Raised when JSON input contains a duplicate object member."""


class CanonicalizationError(ValueError):
    """Raised when a value is outside the portable JCS subset."""


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_json_constant(token: str) -> Any:
    raise ValueError(f"non-JSON numeric constant is forbidden: {token}")


def _load_json_bytes(data: bytes, label: str, errors: list[str]) -> Any | None:
    try:
        text = data.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=_pairs_no_duplicates,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        errors.append(f"{label}: invalid closed JSON input: {exc}")
        return None


def _validate_unicode(value: str, where: str) -> None:
    if unicodedata.normalize("NFC", value) != value:
        raise CanonicalizationError(f"{where}: string is not Unicode NFC")
    try:
        value.encode("utf-8", errors="strict")
        value.encode("utf-16-be", errors="strict")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError(f"{where}: unpaired Unicode surrogate") from exc


def _utf16_sort_key(value: str) -> bytes:
    _validate_unicode(value, "object key")
    return value.encode("utf-16-be")


def _canonical_text(value: Any, where: str = "$") -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > SAFE_INTEGER:
            raise CanonicalizationError(
                f"{where}: integer {value} is outside the interoperable safe range"
            )
        return str(value)
    if isinstance(value, float):
        raise CanonicalizationError(f"{where}: floating-point values are forbidden")
    if isinstance(value, str):
        _validate_unicode(value, where)
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(
            _canonical_text(item, f"{where}[{index}]")
            for index, item in enumerate(value)
        ) + "]"
    if isinstance(value, Mapping):
        members: list[str] = []
        for key in value:
            if not isinstance(key, str):
                raise CanonicalizationError(f"{where}: JSON object key is not a string")
        for key in sorted(value, key=_utf16_sort_key):
            _validate_unicode(key, f"{where} object key")
            members.append(
                json.dumps(key, ensure_ascii=False, separators=(",", ":"))
                + ":"
                + _canonical_text(value[key], f"{where}.{key}")
            )
        return "{" + ",".join(members) + "}"
    raise CanonicalizationError(
        f"{where}: unsupported JSON value type {type(value).__name__}"
    )


def canonical_json_bytes(value: Any) -> bytes:
    """Return CANONICAL-JSON-V1 bytes for the repository's strict JCS subset."""

    return _canonical_text(value).encode("utf-8")


def sha256(data: bytes | bytearray | memoryview) -> str:
    """Return a repository-format SHA-256 digest for exact bytes."""

    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("sha256() requires bytes-like input")
    return "sha256:" + hashlib.sha256(bytes(data)).hexdigest()


def _canonical_digest(value: Any, label: str, errors: list[str]) -> str | None:
    try:
        return sha256(canonical_json_bytes(value))
    except (CanonicalizationError, TypeError, ValueError) as exc:
        errors.append(f"{label}: cannot canonicalize: {exc}")
        return None


def _coerce_document(value: Any, label: str, errors: list[str]) -> Any | None:
    if isinstance(value, (str, os.PathLike)):
        path = Path(value)
        try:
            data = path.read_bytes()
        except OSError as exc:
            errors.append(f"{label}: cannot read {path}: {exc}")
            return None
        return _load_json_bytes(data, f"{label} ({path})", errors)
    if isinstance(value, Mapping):
        try:
            canonical_json_bytes(value)
        except (CanonicalizationError, TypeError, ValueError) as exc:
            errors.append(f"{label}: invalid canonical value: {exc}")
            return None
        return copy.deepcopy(dict(value))
    errors.append(f"{label}: expected a JSON object or a path")
    return None


def _exact_keys(
    value: Any,
    required: Iterable[str],
    label: str,
    errors: list[str],
    *,
    optional: Iterable[str] = (),
) -> bool:
    if not isinstance(value, Mapping):
        errors.append(f"{label}: expected object")
        return False
    required_set = set(required)
    allowed = required_set | set(optional)
    actual = set(value)
    missing = sorted(required_set - actual)
    unknown = sorted(actual - allowed)
    if missing:
        errors.append(f"{label}: missing required fields {missing}")
    if unknown:
        errors.append(f"{label}: unknown fields {unknown}")
    return not missing and not unknown


def _is_digest(value: Any, label: str, errors: list[str], *, nonzero: bool = False) -> bool:
    if not isinstance(value, str) or DIGEST_RE.fullmatch(value) is None:
        errors.append(f"{label}: expected sha256:<64 lowercase hex>")
        return False
    if nonzero and value == ZERO_DIGEST:
        errors.append(f"{label}: all-zero fixture digest is not evidence")
        return False
    return True


def _nonempty_string(
    value: Any,
    label: str,
    errors: list[str],
    *,
    max_length: int | None = None,
) -> str | None:
    if not isinstance(value, str) or not value:
        errors.append(f"{label}: expected non-empty string")
        return None
    if max_length is not None and len(value) > max_length:
        errors.append(f"{label}: exceeds maximum length {max_length}")
        return None
    return value


def _nullable_digest(
    value: Any,
    label: str,
    errors: list[str],
    *,
    nonzero: bool = False,
) -> None:
    if value is not None:
        _is_digest(value, label, errors, nonzero=nonzero)


def _unique_strings(value: Any, label: str, errors: list[str], *, nonempty: bool = True) -> list[str]:
    if not isinstance(value, list):
        errors.append(f"{label}: expected array")
        return []
    if nonempty and not value:
        errors.append(f"{label}: must not be empty")
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            errors.append(f"{label}[{index}]: expected non-empty string")
        else:
            result.append(item)
    if len(result) != len(set(result)):
        errors.append(f"{label}: duplicate values are forbidden")
    return result


def _require_canonical_set_order(value: Any, label: str, errors: list[str]) -> None:
    """Require a schema-known set array to be deduplicated and byte-sorted.

    RFC 8785 itself preserves arrays.  CANONICAL-JSON-V1 additionally requires
    schema-declared sets to be normalized *before* hashing, so this semantic
    layer rejects a non-normalized producer instead of silently rewriting its
    signed input.
    """

    if not isinstance(value, list):
        return
    encoded: list[bytes] = []
    for index, item in enumerate(value):
        try:
            encoded.append(canonical_json_bytes(item))
        except (CanonicalizationError, TypeError, ValueError) as exc:
            errors.append(f"{label}[{index}]: cannot canonicalize set element: {exc}")
            return
    if len(encoded) != len(set(encoded)):
        errors.append(f"{label}: duplicate canonical set element")
    if encoded != sorted(encoded):
        errors.append(f"{label}: set elements are not sorted by canonical bytes")


def _safe_relative_path(value: Any, label: str, errors: list[str]) -> str | None:
    if not isinstance(value, str) or not value:
        errors.append(f"{label}: expected a non-empty repository-relative path")
        return None
    if "\\" in value or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        errors.append(f"{label}: backslashes and ASCII control characters are forbidden")
        return None
    candidate = PurePosixPath(value)
    if candidate.is_absolute() or any(part in ("", ".", "..") for part in candidate.parts):
        errors.append(f"{label}: path must be normalized and must not escape its root")
        return None
    return candidate.as_posix()


def _normal_commit(value: Any, label: str, errors: list[str]) -> str | None:
    if not isinstance(value, str) or COMMIT_RE.fullmatch(value) is None:
        errors.append(f"{label}: expected a full 40- or 64-hex git commit")
        return None
    result = value[4:] if value.startswith("git:") else value
    return result.lower()


def _parse_time(value: Any, label: str, errors: list[str]) -> _datetime.datetime | None:
    if not isinstance(value, str) or re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", value
    ) is None:
        errors.append(
            f"{label}: expected TIMESTAMP-UTC-US-V1 (UTC RFC 3339, exactly six fractional digits and Z)"
        )
        return None
    try:
        text = value[:-1] + "+00:00"
        result = _datetime.datetime.fromisoformat(text)
        if result.tzinfo is None:
            raise ValueError("timezone is required")
        return result.astimezone(_datetime.timezone.utc)
    except ValueError as exc:
        errors.append(f"{label}: invalid RFC 3339 date-time: {exc}")
        return None


class _GitView:
    def __init__(
        self,
        root: Path,
        repository: Mapping[str, Any],
        errors: list[str],
        authority_label: str = "targetRepository",
        *,
        _submodule_depth: int = 0,
        _submodule_budget: list[int] | None = None,
    ):
        self.authority_label = authority_label
        self.path: Path | None = None
        self.artifact_root: str | None = None
        self.forbidden_blob_claims: tuple[bytes, ...] = ()
        self._submodule_depth = _submodule_depth
        self._submodule_budget = (
            _submodule_budget if _submodule_budget is not None else [256]
        )
        self.commit: str | None = _normal_commit(
            repository.get("commit"), f"{authority_label}.commit", errors
        )
        object_format = repository.get("objectFormat")
        if object_format not in {"SHA1", "SHA256"}:
            errors.append(f"{authority_label}.objectFormat: expected SHA1 or SHA256")
        elif self.commit is not None:
            expected_length = 40 if object_format == "SHA1" else 64
            if len(self.commit) != expected_length:
                errors.append(
                    f"{authority_label}.commit: {object_format} requires {expected_length} hex digits"
                )
        if authority_label == "evidenceRepository":
            self.artifact_root = _safe_relative_path(
                repository.get("artifactRoot"),
                f"{authority_label}.artifactRoot",
                errors,
            )
        location = repository.get("repositoryLocation")
        if not isinstance(location, str) or not location:
            errors.append(f"{authority_label}.repositoryLocation: local checkout is required")
            return
        if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", location):
            errors.append(
                f"{authority_label}.repositoryLocation: network URLs are not executable proof; provide a local checkout"
            )
            return
        path = Path(location)
        if not path.is_absolute():
            path = root / path
        try:
            path = path.resolve(strict=True)
        except OSError as exc:
            errors.append(f"{authority_label}.repositoryLocation: cannot resolve {path}: {exc}")
            return
        if not path.is_dir():
            errors.append(f"{authority_label}.repositoryLocation: {path} is not a directory")
            return
        self.path = path
        observed_format = self._run(["rev-parse", "--show-object-format"])
        if observed_format is None:
            errors.append(f"{authority_label}.objectFormat: cannot query local Git object format")
        elif object_format in {"SHA1", "SHA256"}:
            observed = observed_format.decode("ascii", errors="replace").strip().upper()
            if observed != object_format:
                errors.append(
                    f"{authority_label}.objectFormat: local repository is {observed}, declared {object_format}"
                )
        if self.commit is not None:
            result = self._run(["rev-parse", "--verify", f"{self.commit}^{{commit}}"])
            if result is None:
                errors.append(f"{authority_label}.commit: {self.commit} is not present in {path}")
            else:
                actual = result.decode("ascii", errors="replace").strip().lower()
                if actual != self.commit:
                    errors.append(
                        f"{authority_label}.commit: resolved {actual}, expected exact {self.commit}"
                    )

    @property
    def ready(self) -> bool:
        return self.path is not None and self.commit is not None

    def _run(self, arguments: Sequence[str]) -> bytes | None:
        if self.path is None:
            return None
        try:
            result = subprocess.run(
                ["git", "-C", str(self.path), *arguments],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if result.returncode != 0:
            return None
        return result.stdout

    def _blob_from_submodule(
        self, safe: str, label: str, errors: list[str]
    ) -> tuple[bool, bytes | None]:
        """Resolve a path through pinned gitlinks with bounded recursion."""

        parts = PurePosixPath(safe).parts
        if len(parts) < 2 or self.path is None or self.commit is None:
            return False, None
        for end in range(1, len(parts)):
            prefix = PurePosixPath(*parts[:end]).as_posix()
            entry = self._run(["ls-tree", "-z", self.commit, "--", prefix])
            if entry is None or not entry:
                continue
            try:
                metadata, exact_path = entry.rstrip(b"\x00").split(b"\t", 1)
                mode, object_type, object_id = metadata.split(b" ", 2)
                decoded_path = exact_path.decode("utf-8", errors="strict")
            except (UnicodeDecodeError, ValueError):
                errors.append(f"{label}: cannot parse gitlink entry for {prefix!r}")
                return True, None
            if decoded_path != prefix or mode != b"160000" or object_type != b"commit":
                continue
            if self._submodule_depth >= 16:
                errors.append(f"{label}: recursive submodule depth exceeds 16")
                return True, None
            if self._submodule_budget[0] <= 0:
                errors.append(f"{label}: recursive submodule traversal exceeds 256")
                return True, None
            self._submodule_budget[0] -= 1
            try:
                submodule_path = self.path.joinpath(*parts[:end]).resolve(strict=True)
                submodule_path.relative_to(self.path.resolve(strict=True))
            except (OSError, ValueError) as exc:
                errors.append(
                    f"{label}: local submodule checkout {prefix!r} is unavailable: {exc}"
                )
                return True, None
            try:
                commit = object_id.decode("ascii", errors="strict").lower()
            except UnicodeDecodeError:
                errors.append(f"{label}: gitlink object ID is not ASCII")
                return True, None
            if len(commit) not in {40, 64} or re.fullmatch(
                r"[0-9a-f]+", commit
            ) is None:
                errors.append(f"{label}: malformed full gitlink object ID")
                return True, None
            object_format = "SHA1" if len(commit) == 40 else "SHA256"
            sub_view = _GitView(
                self.path,
                {
                    "repositoryLocation": str(submodule_path),
                    "objectFormat": object_format,
                    "commit": commit,
                },
                errors,
                f"{self.authority_label}.submodule[{prefix}]",
                _submodule_depth=self._submodule_depth + 1,
                _submodule_budget=self._submodule_budget,
            )
            remainder = PurePosixPath(*parts[end:]).as_posix()
            result = sub_view.blob(remainder, label, errors)
            if result is not None and self.authority_label == "evidenceRepository":
                lowered = result.lower()
                forbidden = list(self.forbidden_blob_claims)
                forbidden.append(self.commit.encode("ascii"))
                embedded = next(
                    (
                        claim
                        for claim in forbidden
                        if claim and claim.lower() in lowered
                    ),
                    None,
                )
                if embedded is not None:
                    errors.append(
                        f"{label}: evidence blob embeds forbidden containing-E/"
                        "final-map identity; the C -> M -> E graph would be "
                        "self-referential"
                    )
            return True, result
        return False, None

    def blob(self, path: Any, label: str, errors: list[str]) -> bytes | None:
        safe = _safe_relative_path(path, label, errors)
        if safe is None or not self.ready:
            if not self.ready:
                errors.append(
                    f"{label}: pinned {self.authority_label} git checkout is unavailable"
                )
            return None
        if self.artifact_root is not None:
            root = PurePosixPath(self.artifact_root)
            candidate = PurePosixPath(safe)
            if candidate != root and root not in candidate.parents:
                errors.append(
                    f"{label}: {safe!r} is outside evidenceRepository.artifactRoot "
                    f"{self.artifact_root!r}"
                )
                return None
        tree_entry = self._run(["ls-tree", "-z", self.commit, "--", safe])
        if tree_entry is None or not tree_entry:
            matched_submodule, submodule_blob = self._blob_from_submodule(
                safe, label, errors
            )
            if matched_submodule:
                return submodule_blob
            errors.append(f"{label}: {safe!r} has no exact tree entry at commit {self.commit}")
            return None
        try:
            metadata, exact_path = tree_entry.rstrip(b"\x00").split(b"\t", 1)
            mode, object_type, _ = metadata.split(b" ", 2)
        except ValueError:
            errors.append(f"{label}: cannot parse exact git tree entry for {safe!r}")
            return None
        if exact_path.decode("utf-8", errors="strict") != safe:
            errors.append(f"{label}: git tree path does not exactly match requested path")
            return None
        if mode not in {b"100644", b"100755"} or object_type != b"blob":
            errors.append(f"{label}: symlink, submodule, or non-regular git entry is forbidden")
            return None
        result = self._run(["cat-file", "blob", f"{self.commit}:{safe}"])
        if result is None:
            errors.append(f"{label}: {safe!r} is not a blob at commit {self.commit}")
        elif self.authority_label == "evidenceRepository":
            lowered = result.lower()
            forbidden = list(self.forbidden_blob_claims)
            if self.commit is not None:
                forbidden.append(self.commit.encode("ascii"))
            embedded = next(
                (claim for claim in forbidden if claim and claim.lower() in lowered),
                None,
            )
            if embedded is not None:
                errors.append(
                    f"{label}: evidence blob embeds forbidden containing-E/final-map "
                    "identity; the C -> M -> E graph would be self-referential"
                )
        return result


def _worktree_bytes(root: Path, path: Any, label: str, errors: list[str]) -> bytes | None:
    safe = _safe_relative_path(path, label, errors)
    if safe is None:
        return None
    candidate = root.joinpath(*PurePosixPath(safe).parts)
    try:
        resolved_root = root.resolve(strict=True)
        cursor = resolved_root
        for part in PurePosixPath(safe).parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise OSError(f"symlink is forbidden: {cursor}")
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(resolved_root)
        if not resolved.is_file():
            raise OSError("not a regular file")
        return resolved.read_bytes()
    except (OSError, ValueError) as exc:
        errors.append(f"{label}: cannot read source artifact {candidate}: {exc}")
        return None


def _check_blob_hash(
    blob: bytes | None, expected: Any, label: str, errors: list[str]
) -> bool:
    if not _is_digest(expected, f"{label}.sha256", errors):
        return False
    if blob is None:
        return False
    actual = sha256(blob)
    if actual != expected:
        errors.append(f"{label}: hash mismatch: declared {expected}, actual {actual}")
        return False
    return True


def _artifact_from_git(
    descriptor: Any, git: _GitView | None, label: str, errors: list[str]
) -> bytes | None:
    if not _exact_keys(descriptor, {"path", "sha256"}, label, errors):
        return None
    if git is None:
        errors.append(f"{label}: pinned target git checkout is unavailable")
        return None
    blob = git.blob(descriptor.get("path"), f"{label}.path", errors)
    _check_blob_hash(blob, descriptor.get("sha256"), label, errors)
    return blob


ARTIFACT_DESCRIPTOR_FIELDS = {"path", "sha256", "schemaRef", "schemaSha256"}


def _typed_artifact_from_git(
    descriptor: Any,
    git: _GitView | None,
    root: Path,
    label: str,
    errors: list[str],
    *,
    expected_schema_ref: str,
    descriptor_fields: Iterable[str] = ARTIFACT_DESCRIPTOR_FIELDS,
) -> bytes | None:
    """Resolve an evidence blob and its exact normative schema independently."""

    if not _exact_keys(descriptor, descriptor_fields, label, errors):
        return None
    if not isinstance(descriptor, Mapping):
        return None
    schema_ref = descriptor.get("schemaRef")
    if schema_ref != expected_schema_ref:
        errors.append(
            f"{label}.schemaRef: expected fixed normative schema {expected_schema_ref!r}"
        )
    schema_path = schema_ref.split("#", 1)[0] if isinstance(schema_ref, str) else None
    schema_blob = _worktree_bytes(root, schema_path, f"{label}.schemaRef", errors)
    _check_blob_hash(
        schema_blob,
        descriptor.get("schemaSha256"),
        f"{label}.schema",
        errors,
    )
    if git is None:
        errors.append(f"{label}: pinned evidence git checkout is unavailable")
        return None
    blob = git.blob(descriptor.get("path"), f"{label}.path", errors)
    _check_blob_hash(blob, descriptor.get("sha256"), label, errors)
    if blob is not None and isinstance(schema_ref, str):
        instance = _load_json_bytes(blob, f"{label} instance", errors)
        if instance is not None:
            _validate_closed_json_schema_instance(
                instance,
                root,
                schema_ref,
                f"{label} instance",
                errors,
            )
    return blob


def _load_worktree_schema_ref(
    root: Path, schema_ref: str, label: str, errors: list[str]
) -> Mapping[str, Any] | None:
    """Load a local JSON schema and resolve an RFC 6901 fragment exactly."""

    path_text, separator, fragment = schema_ref.partition("#")
    blob = _worktree_bytes(root, path_text, f"{label}.path", errors)
    document = _load_json_bytes(blob, label, errors) if blob is not None else None
    if not isinstance(document, Mapping):
        return None
    if not separator or fragment == "":
        return document
    if not fragment.startswith("/"):
        errors.append(f"{label}: only an RFC 6901 JSON Pointer fragment is supported")
        return None
    current: Any = document
    for raw_token in fragment[1:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, Mapping) or token not in current:
            errors.append(f"{label}: JSON Pointer fragment does not resolve at {token!r}")
            return None
        current = current[token]
    if not isinstance(current, Mapping):
        errors.append(f"{label}: JSON Pointer must resolve to an object schema")
        return None
    return current


_UNSUPPORTED_CLOSED_SCHEMA_KEYWORDS = {
    "$anchor",
    "$dynamicAnchor",
    "$dynamicRef",
    "dependentRequired",
    "dependentSchemas",
    "exclusiveMaximum",
    "exclusiveMinimum",
    "multipleOf",
    "patternProperties",
    "prefixItems",
    "unevaluatedItems",
    "unevaluatedProperties",
}


def _validate_closed_json_schema_instance(
    instance: Any,
    root: Path,
    schema_ref: str,
    label: str,
    errors: list[str],
) -> None:
    """Validate an instance against the closed schema subset used by this package.

    This is deliberately not advertised as a general Draft 2020-12 engine.  It
    implements every assertion keyword currently used by the signed portable
    artifacts and fails closed if one of the known unsupported assertion
    keywords appears.  Cross-document cryptographic and repository semantics
    remain the responsibility of the explicit validators below.
    """

    schema_cache: dict[str, Mapping[str, Any]] = {}

    def normalize_schema_path(base_path: str, reference_path: str) -> str | None:
        candidate = PurePosixPath(base_path).parent / PurePosixPath(reference_path)
        normalized: list[str] = []
        for part in candidate.parts:
            if part in {"", "."}:
                continue
            if part == "..":
                if not normalized:
                    return None
                normalized.pop()
            else:
                normalized.append(part)
        if not normalized:
            return None
        return PurePosixPath(*normalized).as_posix()

    def load_schema(path: str, where: str, target_errors: list[str]) -> Mapping[str, Any] | None:
        cached = schema_cache.get(path)
        if cached is not None:
            return cached
        blob = _worktree_bytes(root, path, f"{where} schema", target_errors)
        document = (
            _load_json_bytes(blob, f"{where} schema", target_errors)
            if blob is not None
            else None
        )
        if not isinstance(document, Mapping):
            target_errors.append(f"{where}: schema document must be an object")
            return None
        schema_cache[path] = document
        return document

    def pointer(
        document: Mapping[str, Any],
        fragment: str,
        where: str,
        target_errors: list[str],
    ) -> Any | None:
        if fragment == "":
            return document
        if not fragment.startswith("/"):
            target_errors.append(
                f"{where}: only RFC 6901 JSON Pointer schema fragments are supported"
            )
            return None
        current: Any = document
        for raw_token in fragment[1:].split("/"):
            token = raw_token.replace("~1", "/").replace("~0", "~")
            if not isinstance(current, Mapping) or token not in current:
                target_errors.append(
                    f"{where}: schema JSON Pointer does not resolve at {token!r}"
                )
                return None
            current = current[token]
        return current

    def resolve_ref(
        reference: Any,
        current_path: str,
        current_document: Mapping[str, Any],
        where: str,
        target_errors: list[str],
    ) -> tuple[Any | None, str, Mapping[str, Any]]:
        if not isinstance(reference, str) or not reference:
            target_errors.append(f"{where}: $ref must be a non-empty string")
            return None, current_path, current_document
        path_text, separator, fragment = reference.partition("#")
        if "://" in path_text or path_text.startswith(("/", "\\")):
            target_errors.append(f"{where}: remote/absolute schema refs are forbidden")
            return None, current_path, current_document
        if path_text:
            resolved_path = normalize_schema_path(current_path, path_text)
            if resolved_path is None:
                target_errors.append(f"{where}: schema ref escapes the package root")
                return None, current_path, current_document
            resolved_document = load_schema(resolved_path, where, target_errors)
            if resolved_document is None:
                return None, resolved_path, current_document
        else:
            resolved_path = current_path
            resolved_document = current_document
        resolved = pointer(
            resolved_document,
            fragment if separator else "",
            where,
            target_errors,
        )
        return resolved, resolved_path, resolved_document

    def json_equal(left: Any, right: Any) -> bool:
        if isinstance(left, bool) or isinstance(right, bool):
            return isinstance(left, bool) and isinstance(right, bool) and left == right
        if left is None or right is None:
            return left is None and right is None
        if type(left) is not type(right):
            return False
        return left == right

    def type_matches(value: Any, expected: str) -> bool:
        return {
            "null": value is None,
            "boolean": isinstance(value, bool),
            "object": isinstance(value, Mapping),
            "array": isinstance(value, list),
            "string": isinstance(value, str),
            "integer": isinstance(value, int) and not isinstance(value, bool),
            "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        }.get(expected, False)

    def branch_matches(
        value: Any,
        branch: Any,
        current_path: str,
        current_document: Mapping[str, Any],
        where: str,
    ) -> tuple[bool, list[str]]:
        branch_errors: list[str] = []
        validate(
            value,
            branch,
            current_path,
            current_document,
            where,
            branch_errors,
        )
        return not branch_errors, branch_errors

    def validate(
        value: Any,
        schema: Any,
        current_path: str,
        current_document: Mapping[str, Any],
        where: str,
        target_errors: list[str],
    ) -> None:
        if schema is True:
            return
        if schema is False:
            target_errors.append(f"{where}: rejected by boolean false schema")
            return
        if not isinstance(schema, Mapping):
            target_errors.append(f"{where}: schema node must be an object or boolean")
            return
        unsupported = sorted(set(schema) & _UNSUPPORTED_CLOSED_SCHEMA_KEYWORDS)
        if unsupported:
            target_errors.append(
                f"{where}: signed-artifact schema uses unsupported constraints "
                f"{unsupported}; validation fails closed"
            )
            return

        reference = schema.get("$ref")
        if reference is not None:
            resolved, resolved_path, resolved_document = resolve_ref(
                reference,
                current_path,
                current_document,
                f"{where}.$ref",
                target_errors,
            )
            if resolved is None:
                return
            validate(
                value,
                resolved,
                resolved_path,
                resolved_document,
                where,
                target_errors,
            )

        expected_type = schema.get("type")
        if expected_type is not None:
            type_names = (
                [expected_type]
                if isinstance(expected_type, str)
                else expected_type
                if isinstance(expected_type, list)
                else []
            )
            if not type_names or not all(isinstance(item, str) for item in type_names):
                target_errors.append(f"{where}: invalid schema type declaration")
                return
            if not any(type_matches(value, item) for item in type_names):
                target_errors.append(
                    f"{where}: expected JSON type {type_names}, found "
                    f"{type(value).__name__}"
                )
                return

        if "const" in schema and not json_equal(value, schema["const"]):
            target_errors.append(f"{where}: value does not equal schema const")
        if "enum" in schema:
            choices = schema["enum"]
            if not isinstance(choices, list) or not any(
                json_equal(value, choice) for choice in choices
            ):
                target_errors.append(f"{where}: value is outside schema enum")

        all_of = schema.get("allOf")
        if all_of is not None:
            if not isinstance(all_of, list):
                target_errors.append(f"{where}: allOf must be an array")
            else:
                for index, branch in enumerate(all_of):
                    validate(
                        value,
                        branch,
                        current_path,
                        current_document,
                        f"{where}.allOf[{index}]",
                        target_errors,
                    )
        any_of = schema.get("anyOf")
        if any_of is not None:
            if not isinstance(any_of, list) or not any_of:
                target_errors.append(f"{where}: anyOf must be a non-empty array")
            else:
                branch_results = [
                    branch_matches(
                        value,
                        branch,
                        current_path,
                        current_document,
                        f"{where}.anyOf[{index}]",
                    )
                    for index, branch in enumerate(any_of)
                ]
                if not any(matched for matched, _ in branch_results):
                    detail = [
                        branch_errors[0]
                        for matched, branch_errors in branch_results
                        if not matched and branch_errors
                    ][:2]
                    target_errors.append(
                        f"{where}: anyOf matched 0 branches, expected at least 1"
                        + (f"; examples={detail}" if detail else "")
                    )
        one_of = schema.get("oneOf")
        if one_of is not None:
            if not isinstance(one_of, list) or not one_of:
                target_errors.append(f"{where}: oneOf must be a non-empty array")
            else:
                branch_results = [
                    branch_matches(
                        value,
                        branch,
                        current_path,
                        current_document,
                        f"{where}.oneOf[{index}]",
                    )
                    for index, branch in enumerate(one_of)
                ]
                match_count = sum(matched for matched, _ in branch_results)
                if match_count != 1:
                    detail = [
                        branch_errors[0]
                        for matched, branch_errors in branch_results
                        if not matched and branch_errors
                    ][:2]
                    target_errors.append(
                        f"{where}: oneOf matched {match_count} branches, expected exactly 1"
                        + (f"; examples={detail}" if detail else "")
                    )

        not_schema = schema.get("not")
        if not_schema is not None:
            matched, _ = branch_matches(
                value,
                not_schema,
                current_path,
                current_document,
                f"{where}.not",
            )
            if matched:
                target_errors.append(f"{where}: value matches forbidden not schema")

        if_schema = schema.get("if")
        if if_schema is not None:
            condition, _ = branch_matches(
                value,
                if_schema,
                current_path,
                current_document,
                f"{where}.if",
            )
            selected_name = "then" if condition else "else"
            if selected_name in schema:
                validate(
                    value,
                    schema[selected_name],
                    current_path,
                    current_document,
                    f"{where}.{selected_name}",
                    target_errors,
                )

        if isinstance(value, Mapping):
            required = schema.get("required")
            if required is not None:
                if not isinstance(required, list) or not all(
                    isinstance(item, str) for item in required
                ):
                    target_errors.append(f"{where}: required must be a string array")
                else:
                    missing = [item for item in required if item not in value]
                    if missing:
                        target_errors.append(f"{where}: missing required fields {missing}")
            properties = schema.get("properties", {})
            if not isinstance(properties, Mapping):
                target_errors.append(f"{where}: properties must be an object")
                properties = {}
            for key, property_schema in properties.items():
                if key in value:
                    validate(
                        value[key],
                        property_schema,
                        current_path,
                        current_document,
                        f"{where}.{key}",
                        target_errors,
                    )
            property_names = schema.get("propertyNames")
            if property_names is not None:
                for key in value:
                    validate(
                        key,
                        property_names,
                        current_path,
                        current_document,
                        f"{where}.propertyName[{key!r}]",
                        target_errors,
                    )
            additional = schema.get("additionalProperties", True)
            extra_keys = set(value) - set(properties)
            if additional is False and extra_keys:
                target_errors.append(
                    f"{where}: additional properties are forbidden {sorted(extra_keys)}"
                )
            elif isinstance(additional, (Mapping, bool)) and additional is not True:
                for key in extra_keys:
                    validate(
                        value[key],
                        additional,
                        current_path,
                        current_document,
                        f"{where}.{key}",
                        target_errors,
                    )
            elif not isinstance(additional, (Mapping, bool)):
                target_errors.append(
                    f"{where}: additionalProperties must be a schema or boolean"
                )
            minimum_properties = schema.get("minProperties")
            if isinstance(minimum_properties, int) and len(value) < minimum_properties:
                target_errors.append(
                    f"{where}: has {len(value)} properties, minimum is {minimum_properties}"
                )
            maximum_properties = schema.get("maxProperties")
            if isinstance(maximum_properties, int) and len(value) > maximum_properties:
                target_errors.append(
                    f"{where}: has {len(value)} properties, maximum is {maximum_properties}"
                )

        if isinstance(value, list):
            minimum_items = schema.get("minItems")
            maximum_items = schema.get("maxItems")
            if isinstance(minimum_items, int) and len(value) < minimum_items:
                target_errors.append(
                    f"{where}: has {len(value)} items, minimum is {minimum_items}"
                )
            if isinstance(maximum_items, int) and len(value) > maximum_items:
                target_errors.append(
                    f"{where}: has {len(value)} items, maximum is {maximum_items}"
                )
            if schema.get("uniqueItems") is True:
                item_keys: list[bytes] = []
                try:
                    item_keys = [canonical_json_bytes(item) for item in value]
                except (CanonicalizationError, TypeError, ValueError) as exc:
                    target_errors.append(f"{where}: cannot compare uniqueItems: {exc}")
                if item_keys and len(item_keys) != len(set(item_keys)):
                    target_errors.append(f"{where}: duplicate array items are forbidden")
            item_schema = schema.get("items")
            if item_schema is not None:
                for index, item in enumerate(value):
                    validate(
                        item,
                        item_schema,
                        current_path,
                        current_document,
                        f"{where}[{index}]",
                        target_errors,
                    )
            contains = schema.get("contains")
            if contains is not None:
                contains_count = sum(
                    branch_matches(
                        item,
                        contains,
                        current_path,
                        current_document,
                        f"{where}[{index}].contains",
                    )[0]
                    for index, item in enumerate(value)
                )
                minimum_contains = schema.get("minContains", 1)
                maximum_contains = schema.get("maxContains")
                if (
                    not isinstance(minimum_contains, int)
                    or isinstance(minimum_contains, bool)
                    or minimum_contains < 0
                ):
                    target_errors.append(f"{where}: minContains must be non-negative")
                elif contains_count < minimum_contains:
                    target_errors.append(
                        f"{where}: {contains_count} items satisfy contains, "
                        f"minimum is {minimum_contains}"
                    )
                if maximum_contains is not None:
                    if (
                        not isinstance(maximum_contains, int)
                        or isinstance(maximum_contains, bool)
                        or maximum_contains < 0
                    ):
                        target_errors.append(
                            f"{where}: maxContains must be non-negative"
                        )
                    elif contains_count > maximum_contains:
                        target_errors.append(
                            f"{where}: {contains_count} items satisfy contains, "
                            f"maximum is {maximum_contains}"
                        )

        if isinstance(value, str):
            minimum_length = schema.get("minLength")
            maximum_length = schema.get("maxLength")
            if isinstance(minimum_length, int) and len(value) < minimum_length:
                target_errors.append(
                    f"{where}: string length {len(value)} is below {minimum_length}"
                )
            if isinstance(maximum_length, int) and len(value) > maximum_length:
                target_errors.append(
                    f"{where}: string length {len(value)} exceeds {maximum_length}"
                )
            pattern = schema.get("pattern")
            if pattern is not None:
                if not isinstance(pattern, str):
                    target_errors.append(f"{where}: schema pattern must be a string")
                else:
                    try:
                        matched = re.search(pattern, value) is not None
                    except re.error as exc:
                        target_errors.append(f"{where}: invalid schema regex: {exc}")
                    else:
                        if not matched:
                            target_errors.append(
                                f"{where}: string does not match schema pattern"
                            )

        if isinstance(value, (int, float)) and not isinstance(value, bool):
            minimum = schema.get("minimum")
            maximum = schema.get("maximum")
            if isinstance(minimum, (int, float)) and value < minimum:
                target_errors.append(f"{where}: value {value} is below minimum {minimum}")
            if isinstance(maximum, (int, float)) and value > maximum:
                target_errors.append(f"{where}: value {value} exceeds maximum {maximum}")

    path_text, separator, fragment = schema_ref.partition("#")
    if not path_text:
        errors.append(f"{label}: top-level schemaRef must include a local path")
        return
    document = load_schema(path_text, label, errors)
    if document is None:
        return
    selected = pointer(document, fragment if separator else "", label, errors)
    if selected is None:
        return
    validate(instance, selected, path_text, document, label, errors)


def _artifact_from_source(
    descriptor: Any, root: Path, label: str, errors: list[str]
) -> bytes | None:
    if not _exact_keys(descriptor, {"path", "sha256"}, label, errors):
        return None
    blob = _worktree_bytes(root, descriptor.get("path"), f"{label}.path", errors)
    _check_blob_hash(blob, descriptor.get("sha256"), label, errors)
    return blob


def derive_mapping_items(contract: Mapping[str, Any]) -> list[dict[str, str]]:
    """Derive the exact ordered integration mapping surface from a contract."""

    selectors: dict[str, list[str]] = {
        "CANONICALIZATION": [item["id"] for item in contract["canonicalizationContract"]["profiles"]],
        "GUARD": [item["id"] for item in contract["safetyGuards"]],
        "EQUIVALENCE": [contract["dynamicCandidateEquivalence"]["id"]],
        "PORT": [item["id"] for item in contract["requiredPorts"]],
        "ENTITY": [item["id"] for item in contract["dataEntities"]],
        "OPERATION": [item["id"] for item in contract["backendNeutralOperations"]],
        "STATE_MACHINE": [item["id"] for item in contract["stateMachines"]],
        "TRANSITION": [
            transition["id"]
            for machine in contract["stateMachines"]
            for transition in machine["transitions"]
        ],
        "CAS_RULE": [item["id"] for item in contract["casRules"]],
        "REASON": [item["code"] for item in contract["errorContract"]["reasonCodes"]],
        "CONFIG": [item["id"] for item in contract["configurationContract"]["settings"]],
        "MIGRATION": [item["id"] for item in contract["migrationContract"]["steps"]],
        "TELEMETRY": [item["id"] for item in contract["telemetryContract"]["metrics"]],
        "TEST": [item["id"] for item in contract["acceptanceObligations"]],
        "PARITY_OBLIGATION": [item["id"] for item in contract["vmwareParityObligations"]],
    }
    default_track = contract["mappingSurface"]["releaseTrackDefault"]
    overrides = {
        (item["kind"], item["contractItemId"]): item["releaseTrack"]
        for item in contract["mappingSurface"].get("releaseTrackOverrides", [])
    }
    result: list[dict[str, str]] = []
    for derivation in contract["mappingSurface"]["derivation"]:
        kind = derivation["kind"]
        if kind not in selectors:
            raise ValueError(f"unsupported mapping derivation kind: {kind}")
        for item_id in selectors[kind]:
            result.append(
                {
                    "contractItemId": item_id,
                    "kind": kind,
                    "releaseTrack": overrides.get((kind, item_id), default_track),
                }
            )
    identities = [(item["kind"], item["contractItemId"]) for item in result]
    if len(identities) != len(set(identities)):
        raise ValueError("portable mapping surface contains duplicate identities")
    unknown_overrides = set(overrides) - set(identities)
    if unknown_overrides:
        raise ValueError(f"release-track override references unknown items: {sorted(unknown_overrides)}")
    return result


VERIFICATION_ROW_FIELDS = {
    "kind",
    "contractItemId",
    "requiredTestObligationIds",
    "requiredCaseIds",
    "requiredOracleClasses",
    "typedCoverageRule",
    "requirementDigest",
}
TYPED_COVERAGE_RULES = {
    "CANONICALIZATION": "CANONICALIZATION_PROFILE_TYPED_TRACE_OR_ALL",
    "GUARD": "GUARD_TYPED_TRACE_OR_ALL",
    "CONFIG": "CONFIG_TYPED_TRACE_OR_ALL",
    "MIGRATION": "MIGRATION_TYPED_TRACE_OR_ALL",
    "TELEMETRY": "TELEMETRY_TYPED_TRACE_OR_ALL",
    "TEST": "TEST_SELF",
    "PARITY_OBLIGATION": "PARITY_DECLARED_TESTS_OR_ALL",
    "PORT": "PORT_TECH_STORY_INTERSECTION_OR_ALL",
    "OPERATION": "OPERATION_OWNER_PORT_OR_ALL",
    "TRANSITION": "TRANSITION_OPERATION_UNION_WITH_CRASH_SIDE_EFFECT_OR_ALL",
    "STATE_MACHINE": "STATE_MACHINE_TRANSITION_UNION_OR_ALL",
    "REASON": "REASON_LISTING_OPERATION_UNION_OR_ALL",
    "CAS_RULE": "CAS_RULE_REFERENCING_TRANSITION_UNION_OR_ALL",
    "EQUIVALENCE": "EQUIVALENCE_TEST_DYNAMIC_OR_ALL",
    "ENTITY": "ENTITY_STATE_MACHINE_UNION_OR_ALL",
}
VERIFICATION_EXPLICIT_CASE_TRACE_KINDS = {
    "requiredPortIds": "PORT",
    "requiredOperationIds": "OPERATION",
    "requiredTransitionIds": "TRANSITION",
    "requiredEntityIds": "ENTITY",
    "requiredReasonIds": "REASON",
}


def _ordered_unique(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _explicit_case_matrix_requirements(
    root: Path,
) -> dict[tuple[str, str], list[str]]:
    """Independently load source Case trace overlays for the mapping matrix."""

    records: dict[str, Mapping[str, Any]] = {}
    for path in sorted((root / "acceptance" / "cases").glob("*.json")):
        local_errors: list[str] = []
        try:
            blob = path.read_bytes()
        except OSError as exc:
            raise ValueError(f"cannot read Case source {path}: {exc}") from exc
        document = _load_json_bytes(
            blob, f"verification Case source {path.relative_to(root)}", local_errors
        )
        if local_errors:
            raise ValueError("; ".join(local_errors))
        if not isinstance(document, Mapping):
            raise ValueError(f"{path.relative_to(root)} is not an object")
        candidates = document.get("records", [document])
        if not isinstance(candidates, list):
            raise ValueError(f"{path.relative_to(root)} records is not an array")
        for record in candidates:
            if not isinstance(record, Mapping):
                raise ValueError(
                    f"{path.relative_to(root)} contains a non-object Case"
                )
            case_id = record.get("id")
            if not isinstance(case_id, str) or not case_id:
                raise ValueError(
                    f"{path.relative_to(root)} contains an invalid Case ID"
                )
            if case_id in records:
                raise ValueError(f"duplicate Case ID {case_id}")
            records[case_id] = record
    if len(records) != 101:
        raise ValueError(
            f"acceptance/cases must contain 101 unique Cases, got {len(records)}"
        )

    result: dict[tuple[str, str], list[str]] = {}
    fields = set(VERIFICATION_EXPLICIT_CASE_TRACE_KINDS)
    for case_id, record in records.items():
        present = {field for field in fields if field in record}
        if present and present != fields:
            raise ValueError(
                f"Case {case_id} explicit trace is partial; missing "
                f"{sorted(fields - present)}"
            )
        if not present:
            continue
        for field, kind in VERIFICATION_EXPLICIT_CASE_TRACE_KINDS.items():
            values = record.get(field)
            if not isinstance(values, list) or any(
                not isinstance(value, str) or not value for value in values
            ):
                raise ValueError(f"Case {case_id} {field} must be a string list")
            if len(values) != len(set(values)) or values != sorted(values):
                raise ValueError(
                    f"Case {case_id} {field} must be unique and ascending"
                )
            if field != "requiredTransitionIds" and not values:
                raise ValueError(f"Case {case_id} {field} must not be empty")
            for item_id in values:
                result.setdefault((kind, item_id), []).append(case_id)
    for identity, case_ids in result.items():
        result[identity] = sorted(set(case_ids), key=canonical_json_bytes)
    return result


def _derive_verification_matrix(
    contract: Mapping[str, Any],
    mapping_items: Sequence[Mapping[str, str]],
    root: Path,
) -> list[dict[str, Any]]:
    """Independently derive the contract-owned verification requirements."""

    obligations = contract["acceptanceObligations"]
    obligation_by_id = {item["id"]: item for item in obligations}
    obligation_order = [item["id"] for item in obligations]
    if len(obligation_by_id) != len(obligations):
        raise ValueError("duplicate acceptance obligation ID")
    if not {"TEST-DYNAMIC", "TEST-CRASH-RECONCILE-AUDIT"}.issubset(
        obligation_by_id
    ):
        raise ValueError("required dynamic/crash acceptance obligations are missing")

    def normalize(candidate_ids: Iterable[str]) -> list[str]:
        candidate = set(candidate_ids)
        unknown = candidate - set(obligation_by_id)
        if unknown:
            raise ValueError(f"unknown acceptance obligations {sorted(unknown)}")
        ordered = [item_id for item_id in obligation_order if item_id in candidate]
        return ordered or list(obligation_order)

    ports = {item["id"]: item for item in contract["requiredPorts"]}
    operations = {
        item["id"]: item for item in contract["backendNeutralOperations"]
    }
    machines = {item["id"]: item for item in contract["stateMachines"]}
    transitions = {
        transition["id"]: transition
        for machine in contract["stateMachines"]
        for transition in machine["transitions"]
    }
    parity = {item["id"]: item for item in contract["vmwareParityObligations"]}
    explicit_requirements = _explicit_case_matrix_requirements(root)
    item_identities = {
        (item["kind"], item["contractItemId"]) for item in mapping_items
    }
    unknown_explicit_items = set(explicit_requirements) - item_identities
    if unknown_explicit_items:
        raise ValueError(
            "explicit Case trace references unknown mapping items "
            f"{sorted(unknown_explicit_items)}"
        )

    port_obligations: dict[str, list[str]] = {}
    for port_id, port in ports.items():
        stories = set(port["techStoryIds"])
        port_obligations[port_id] = normalize(
            obligation["id"]
            for obligation in obligations
            if stories & set(obligation["techStoryIds"])
        )
    operation_obligations = {
        operation_id: list(port_obligations[operation["ownerPortId"]])
        for operation_id, operation in operations.items()
    }
    transition_obligations: dict[str, list[str]] = {}
    for transition_id, transition in transitions.items():
        candidates = [
            obligation_id
            for operation_id in transition["operationIds"]
            for obligation_id in operation_obligations[operation_id]
        ]
        if any(
            operations[operation_id]["sideEffect"] != "NONE"
            for operation_id in transition["operationIds"]
        ):
            candidates.append("TEST-CRASH-RECONCILE-AUDIT")
        transition_obligations[transition_id] = normalize(_ordered_unique(candidates))
    machine_obligations: dict[str, list[str]] = {}
    entity_candidates: dict[str, list[str]] = {}
    for machine_id, machine in machines.items():
        candidates = [
            obligation_id
            for transition in machine["transitions"]
            for obligation_id in transition_obligations[transition["id"]]
        ]
        derived = normalize(_ordered_unique(candidates))
        machine_obligations[machine_id] = derived
        entity_candidates.setdefault(machine["entityId"], []).extend(derived)
    entity_obligations = {
        entity_id: normalize(_ordered_unique(candidates))
        for entity_id, candidates in entity_candidates.items()
    }
    cas_obligations = {
        rule["id"]: normalize(
            _ordered_unique(
                obligation_id
                for transition in transitions.values()
                if rule["id"] in transition["casRuleIds"]
                for obligation_id in transition_obligations[transition["id"]]
            )
        )
        for rule in contract["casRules"]
    }
    reason_obligations = {
        reason["code"]: normalize(
            _ordered_unique(
                obligation_id
                for operation in operations.values()
                if reason["code"] in operation["failureReasonCodes"]
                for obligation_id in operation_obligations[operation["id"]]
            )
        )
        for reason in contract["errorContract"]["reasonCodes"]
    }

    def obligations_for(kind: str, item_id: str) -> list[str]:
        if kind == "TEST":
            return normalize([item_id])
        if kind == "PARITY_OBLIGATION":
            return normalize(parity[item_id]["testObligationIds"])
        if kind == "PORT":
            return port_obligations[item_id]
        if kind == "OPERATION":
            return operation_obligations[item_id]
        if kind == "TRANSITION":
            return transition_obligations[item_id]
        if kind == "STATE_MACHINE":
            return machine_obligations[item_id]
        if kind == "REASON":
            return reason_obligations[item_id]
        if kind == "CAS_RULE":
            return cas_obligations[item_id]
        if kind == "EQUIVALENCE":
            return normalize(["TEST-DYNAMIC"])
        if kind == "ENTITY" and item_id in entity_obligations:
            return entity_obligations[item_id]
        return list(obligation_order)

    oracle_classes = sorted(ORACLE_CATEGORY_FIELDS)
    result: list[dict[str, Any]] = []
    for item in mapping_items:
        kind = item["kind"]
        item_id = item["contractItemId"]
        required_obligations = obligations_for(kind, item_id)
        required_cases = _ordered_unique(
            [
                case_id
                for obligation_id in required_obligations
                for case_id in obligation_by_id[obligation_id]["caseIds"]
            ]
            + explicit_requirements.get((kind, item_id), [])
        )
        row: dict[str, Any] = {
            "kind": kind,
            "contractItemId": item_id,
            "requiredTestObligationIds": required_obligations,
            "requiredCaseIds": required_cases,
            "requiredOracleClasses": oracle_classes,
            "typedCoverageRule": TYPED_COVERAGE_RULES.get(
                kind, "CONSERVATIVE_ALL"
            ),
        }
        row["requirementDigest"] = sha256(canonical_json_bytes(row))
        result.append(row)
    return result


ROOT_SET_FIELDS = {
    "schemaVersion",
    "rootSetId",
    "verificationPolicy",
    "keys",
    "rootSetDigest",
}
ROOT_VERIFICATION_POLICY_FIELDS = {
    "policyId",
    "requiredSignatures",
    "allowedKeyIds",
}
ROOT_KEY_FIELDS = {
    "keyId",
    "principalId",
    "algorithm",
    "publicKeyBase64Url",
    "notBefore",
    "notAfter",
}
KEY_RING_FIELDS = {
    "schemaVersion",
    "keyRingId",
    "keyRingSequence",
    "previousKeyRingDigest",
    "minimumReaderSchemaVersion",
    "keys",
    "revokedKeyIds",
    "notBefore",
    "expiresAt",
    "rootSignatures",
    "keyRingDigest",
}
KEY_FIELDS = {
    "keyId",
    "principalId",
    "algorithm",
    "publicKeyBase64Url",
    "roles",
    "notBefore",
    "notAfter",
    "revokedAtOrNull",
}
ROOT_SIGNATURE_FIELDS = {"rootKeyId", "signature", "signedAt"}
ROLLBACK_FIELDS = {
    "schemaVersion",
    "recordType",
    "canonicalProfileId",
    "recordState",
    "keyRingId",
    "minimumSequence",
    "acceptedKeyRingDigest",
    "anchorVersion",
    "resourceVersion",
    "previousAnchorDigestOrNull",
    "updatedAt",
    "authorityId",
    "casPrecondition",
    "anchorDigest",
}
TRUST_ROLLBACK_CAS_FIELDS = {
    "expectedAnchorVersionOrNull",
    "expectedResourceVersionOrNull",
    "expectedMinimumSequenceOrNull",
    "expectedAcceptedKeyRingDigestOrNull",
    "expectedAnchorDigestOrNull",
}
TRUST_KEY_RING_HISTORY_FIELDS = {
    "schemaVersion",
    "historyId",
    "rootSetDigest",
    "keyRingId",
    "currentKeyRingSequence",
    "currentKeyRingDigest",
    "rings",
    "historyDigest",
}
TRUST_KEY_RING_HISTORY_DESCRIPTOR_FIELDS = {
    "path",
    "sha256",
    "schemaRef",
    "schemaSha256",
    "keyRingId",
    "keyRingSequence",
    "previousKeyRingDigest",
    "keyRingDigest",
}
ANCHOR_FRESHNESS_FIELDS = {
    "schemaVersion",
    "envelopeId",
    "anchorKind",
    "authorityId",
    "subjectId",
    "anchorPath",
    "anchorBlobSha256",
    "anchorSchemaRef",
    "anchorSchemaSha256",
    "anchorDigest",
    "anchorVersion",
    "resourceVersion",
    "observedAt",
    "expiresAt",
    "verifierNonce",
    "trustRootDigest",
    "freshnessReceiptDigest",
    "rootSignatures",
}
ANCHOR_FRESHNESS_ROOT_SIGNATURE_FIELDS = {
    "rootKeyId",
    "signedAt",
    "algorithm",
    "signature",
}


class _TrustContext:
    def __init__(
        self,
        root_set: Mapping[str, Any],
        key_ring: Mapping[str, Any],
        rollback_anchor: Mapping[str, Any],
        key_ring_history: Mapping[str, Any] | None = None,
        trust_anchor_freshness: Mapping[str, Any] | None = None,
    ):
        self.root_set = root_set
        self.key_ring = key_ring
        self.rollback_anchor = rollback_anchor
        self.key_ring_history = key_ring_history
        self.trust_anchor_freshness = trust_anchor_freshness
        self.keys = {
            item.get("keyId"): item
            for item in key_ring.get("keys", [])
            if isinstance(item, Mapping) and isinstance(item.get("keyId"), str)
        }


def _base64url_decode(
    value: Any, expected_length: int, label: str, errors: list[str]
) -> bytes | None:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        errors.append(f"{label}: invalid unpadded base64url")
        return None
    try:
        decoded = base64.urlsafe_b64decode(value + ("=" * ((-len(value)) % 4)))
    except (ValueError, base64.binascii.Error) as exc:
        errors.append(f"{label}: invalid base64url: {exc}")
        return None
    if len(decoded) != expected_length:
        errors.append(f"{label}: decoded length is {len(decoded)}, expected {expected_length}")
        return None
    if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        errors.append(f"{label}: non-canonical base64url encoding")
        return None
    return decoded


def _verify_ed25519(
    public_key_text: Any,
    signature_text: Any,
    preimage: bytes,
    label: str,
    errors: list[str],
) -> bool:
    if not isinstance(signature_text, str) or SIGNATURE_RE.fullmatch(signature_text) is None:
        errors.append(f"{label}: malformed Ed25519 signature")
        return False
    public_key = _base64url_decode(public_key_text, 32, f"{label}.publicKey", errors)
    signature = _base64url_decode(signature_text[len("ed25519:"):], 64, f"{label}.signature", errors)
    if public_key is None or signature is None:
        return False
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except (ImportError, ModuleNotFoundError) as exc:
        errors.append(
            f"{label}: cryptography is unavailable; signature verification cannot be skipped ({exc})"
        )
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, preimage)
        return True
    except Exception as exc:  # InvalidSignature differs between cryptography versions.
        errors.append(f"{label}: Ed25519 signature verification failed: {type(exc).__name__}")
        return False


def _validate_root_set(root_set: Any, expected: Any, label: str, errors: list[str]) -> None:
    if not _exact_keys(root_set, ROOT_SET_FIELDS, label, errors):
        return
    if root_set.get("schemaVersion") != 1:
        errors.append(f"{label}.schemaVersion: expected 1")
    keys = root_set.get("keys")
    if not isinstance(keys, list) or not keys:
        errors.append(f"{label}.keys: at least one root key is required")
        keys = []
    _require_canonical_set_order(keys, f"{label}.keys", errors)
    key_ids: list[str] = []
    key_materials: list[bytes] = []
    principal_ids: list[str] = []
    for index, key in enumerate(keys):
        key_label = f"{label}.keys[{index}]"
        _exact_keys(key, ROOT_KEY_FIELDS, key_label, errors)
        if not isinstance(key, Mapping):
            continue
        key_id = key.get("keyId")
        if not isinstance(key_id, str) or not key_id:
            errors.append(f"{key_label}.keyId: expected non-empty string")
        else:
            key_ids.append(key_id)
        principal_id = key.get("principalId")
        if isinstance(principal_id, str) and principal_id:
            # Keep quorum cardinality and duplicate-principal checks independent
            # from the identifier-format diagnostic.  A malformed identifier is
            # still rejected below, but it must not make an otherwise present
            # principal disappear and produce a misleading ``1..0`` bound.
            principal_ids.append(principal_id)
        if (
            not isinstance(principal_id, str)
            or re.fullmatch(
                r"urn:qman:principal:[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}",
                principal_id,
            )
            is None
        ):
            errors.append(f"{key_label}.principalId: invalid immutable principal URN")
        if key.get("algorithm") != "Ed25519":
            errors.append(f"{key_label}.algorithm: only Ed25519 is allowed")
        material = _base64url_decode(
            key.get("publicKeyBase64Url"),
            32,
            f"{key_label}.publicKeyBase64Url",
            errors,
        )
        if material is not None:
            key_materials.append(material)
        before = _parse_time(key.get("notBefore"), f"{key_label}.notBefore", errors)
        after = _parse_time(key.get("notAfter"), f"{key_label}.notAfter", errors)
        if before is not None and after is not None and before >= after:
            errors.append(f"{key_label}: notBefore must precede notAfter")
    if len(key_ids) != len(set(key_ids)):
        errors.append(f"{label}.keys: duplicate keyId")
    if len(key_materials) != len(set(key_materials)):
        errors.append(
            f"{label}.keys: distinct keyId values must use distinct Ed25519 public keys"
        )
    if len(principal_ids) != len(set(principal_ids)):
        errors.append(
            f"{label}.keys: one principalId may contribute at most one root quorum key"
        )
    policy = root_set.get("verificationPolicy")
    _exact_keys(
        policy,
        ROOT_VERIFICATION_POLICY_FIELDS,
        f"{label}.verificationPolicy",
        errors,
    )
    if isinstance(policy, Mapping):
        if policy.get("policyId") != "N_OF_M_ED25519_DISTINCT_KEYS_V1":
            errors.append(f"{label}.verificationPolicy.policyId: unsupported policy")
        allowed = _unique_strings(
            policy.get("allowedKeyIds"),
            f"{label}.verificationPolicy.allowedKeyIds",
            errors,
        )
        _require_canonical_set_order(
            policy.get("allowedKeyIds"),
            f"{label}.verificationPolicy.allowedKeyIds",
            errors,
        )
        if set(allowed) != set(key_ids):
            errors.append(
                f"{label}.verificationPolicy.allowedKeyIds: must equal the exact "
                "root keys[*].keyId set"
            )
        required = policy.get("requiredSignatures")
        if (
            not isinstance(required, int)
            or isinstance(required, bool)
            or required < 1
            or required > len(set(principal_ids))
        ):
            errors.append(
                f"{label}.verificationPolicy.requiredSignatures: expected 1.."
                f"{len(set(principal_ids))} distinct principals"
            )
    projection = copy.deepcopy(dict(root_set))
    projection["rootSetDigest"] = None
    actual = _canonical_digest(projection, f"{label} projection", errors)
    if actual is not None and root_set.get("rootSetDigest") != actual:
        errors.append(
            f"{label}.rootSetDigest: declared {root_set.get('rootSetDigest')}, actual {actual}"
        )
    if actual is not None and expected != actual:
        errors.append(f"trustPolicy.expectedTrustRootDigest: expected {expected}, actual {actual}")


def _validate_key_ring_shape(key_ring: Any, label: str, errors: list[str]) -> None:
    if not _exact_keys(key_ring, KEY_RING_FIELDS, label, errors):
        return
    if key_ring.get("schemaVersion") != 1:
        errors.append(f"{label}.schemaVersion: expected 1")
    sequence = key_ring.get("keyRingSequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        errors.append(f"{label}.keyRingSequence: expected positive integer")
    if key_ring.get("minimumReaderSchemaVersion") != 1:
        errors.append(f"{label}.minimumReaderSchemaVersion: unsupported reader version")
    previous = key_ring.get("previousKeyRingDigest")
    if previous is not None:
        _is_digest(previous, f"{label}.previousKeyRingDigest", errors)
    if isinstance(sequence, int) and sequence > 1 and previous is None:
        errors.append(f"{label}.previousKeyRingDigest: required after sequence 1")
    before = _parse_time(key_ring.get("notBefore"), f"{label}.notBefore", errors)
    after = _parse_time(key_ring.get("expiresAt"), f"{label}.expiresAt", errors)
    if before is not None and after is not None and before >= after:
        errors.append(f"{label}: notBefore must precede expiresAt")
    revoked = _unique_strings(
        key_ring.get("revokedKeyIds"), f"{label}.revokedKeyIds", errors, nonempty=False
    )
    _require_canonical_set_order(key_ring.get("revokedKeyIds"), f"{label}.revokedKeyIds", errors)
    keys = key_ring.get("keys")
    if not isinstance(keys, list) or not keys:
        errors.append(f"{label}.keys: at least one signer key is required")
        keys = []
    _require_canonical_set_order(keys, f"{label}.keys", errors)
    ids: list[str] = []
    key_materials: list[bytes] = []
    principals_by_role: dict[str, set[str]] = {}
    allowed_roles = {
        "HOST_INVENTORY_EVIDENCE",
        "QUALIFICATION_ENGINEERING",
        "PRODUCT_RELEASE",
        "HOST_RELEASE_EVIDENCE",
        "CONTROL_REPOSITORY_EVIDENCE",
        "TEST_EVIDENCE",
        "TARGET_ARCHITECT",
        "SECURITY",
        "TEST",
    }
    for index, key in enumerate(keys):
        key_label = f"{label}.keys[{index}]"
        _exact_keys(key, KEY_FIELDS, key_label, errors)
        if not isinstance(key, Mapping):
            continue
        key_id = key.get("keyId")
        if not isinstance(key_id, str) or not key_id:
            errors.append(f"{key_label}.keyId: expected non-empty string")
        else:
            ids.append(key_id)
        principal_id = key.get("principalId")
        if (
            not isinstance(principal_id, str)
            or re.fullmatch(
                r"urn:qman:principal:[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}",
                principal_id,
            )
            is None
        ):
            errors.append(f"{key_label}.principalId: invalid immutable principal URN")
        if key.get("algorithm") != "Ed25519":
            errors.append(f"{key_label}.algorithm: only Ed25519 is allowed")
        material = _base64url_decode(
            key.get("publicKeyBase64Url"),
            32,
            f"{key_label}.publicKeyBase64Url",
            errors,
        )
        if material is not None:
            key_materials.append(material)
        roles = _unique_strings(key.get("roles"), f"{key_label}.roles", errors)
        _require_canonical_set_order(key.get("roles"), f"{key_label}.roles", errors)
        unknown_roles = sorted(set(roles) - allowed_roles)
        if unknown_roles:
            errors.append(f"{key_label}.roles: unknown roles {unknown_roles}")
        role_set = set(roles)
        if isinstance(principal_id, str):
            for role in role_set:
                principals_by_role.setdefault(role, set()).add(principal_id)
        if {"QUALIFICATION_ENGINEERING", "PRODUCT_RELEASE"}.issubset(role_set):
            errors.append(
                f"{key_label}.roles: Qualification Engineering and Product Release must use distinct keys"
            )
        if {"HOST_RELEASE_EVIDENCE", "CONTROL_REPOSITORY_EVIDENCE"}.issubset(
            role_set
        ):
            errors.append(
                f"{key_label}.roles: host release evidence and repository "
                "acceptance evidence must use distinct keys"
            )
        governed_approval_roles = role_set & {"TARGET_ARCHITECT", "SECURITY", "TEST"}
        if len(governed_approval_roles) > 1:
            errors.append(
                f"{key_label}.roles: TARGET_ARCHITECT, SECURITY, and TEST are mutually separated duties"
            )
        key_before = _parse_time(key.get("notBefore"), f"{key_label}.notBefore", errors)
        key_after = _parse_time(key.get("notAfter"), f"{key_label}.notAfter", errors)
        if key_before is not None and key_after is not None and key_before >= key_after:
            errors.append(f"{key_label}: notBefore must precede notAfter")
        revoked_at = key.get("revokedAtOrNull")
        if revoked_at is not None:
            _parse_time(revoked_at, f"{key_label}.revokedAtOrNull", errors)
    if len(ids) != len(set(ids)):
        errors.append(f"{label}.keys: duplicate keyId")
    if len(key_materials) != len(set(key_materials)):
        errors.append(
            f"{label}.keys: distinct keyId values must use distinct Ed25519 public keys"
        )
    if principals_by_role.get("QUALIFICATION_ENGINEERING", set()) & principals_by_role.get(
        "PRODUCT_RELEASE", set()
    ):
        errors.append(
            f"{label}.keys: Qualification Engineering and Product Release "
            "principalIds must be disjoint"
        )
    host_repository_overlap = principals_by_role.get(
        "HOST_RELEASE_EVIDENCE", set()
    ) & principals_by_role.get("CONTROL_REPOSITORY_EVIDENCE", set())
    if host_repository_overlap:
        errors.append(
            f"{label}.keys: HOST_RELEASE_EVIDENCE and "
            "CONTROL_REPOSITORY_EVIDENCE principalIds must be disjoint; "
            f"overlap {sorted(host_repository_overlap)}"
        )
    governed_roles = ("TARGET_ARCHITECT", "SECURITY", "TEST")
    for left_index, left_role in enumerate(governed_roles):
        for right_role in governed_roles[left_index + 1 :]:
            overlap = principals_by_role.get(left_role, set()) & principals_by_role.get(
                right_role, set()
            )
            if overlap:
                errors.append(
                    f"{label}.keys: {left_role} and {right_role} principalIds "
                    f"overlap {sorted(overlap)}"
                )
    unknown_revocations = sorted(set(revoked) - set(ids))
    if unknown_revocations:
        errors.append(f"{label}.revokedKeyIds: unknown key IDs {unknown_revocations}")
    signatures = key_ring.get("rootSignatures")
    if not isinstance(signatures, list) or not signatures:
        errors.append(f"{label}.rootSignatures: at least one signature is required")
        signatures = []
    _require_canonical_set_order(signatures, f"{label}.rootSignatures", errors)
    signature_roots: list[str] = []
    for index, signature in enumerate(signatures):
        sig_label = f"{label}.rootSignatures[{index}]"
        _exact_keys(signature, ROOT_SIGNATURE_FIELDS, sig_label, errors)
        if isinstance(signature, Mapping):
            signature_roots.append(signature.get("rootKeyId"))
            if not isinstance(signature.get("signature"), str) or SIGNATURE_RE.fullmatch(signature["signature"]) is None:
                errors.append(f"{sig_label}.signature: malformed Ed25519 signature")
            _parse_time(signature.get("signedAt"), f"{sig_label}.signedAt", errors)
    if len(signature_roots) != len(set(signature_roots)):
        errors.append(f"{label}.rootSignatures: duplicate rootKeyId")


def _verify_root_digest_quorum(
    root_set: Mapping[str, Any],
    signatures: Any,
    *,
    digest_field: str,
    digest: Any,
    domain: str,
    label: str,
    errors: list[str],
    require_algorithm: bool = False,
) -> None:
    roots = {
        item.get("keyId"): item
        for item in root_set.get("keys", [])
        if isinstance(item, Mapping) and isinstance(item.get("keyId"), str)
    }
    policy = root_set.get("verificationPolicy")
    allowed = set(policy.get("allowedKeyIds", [])) if isinstance(policy, Mapping) else set()
    required = policy.get("requiredSignatures") if isinstance(policy, Mapping) else None
    if not isinstance(required, int) or isinstance(required, bool) or required < 1:
        errors.append(f"{label}: invalid externally pinned root quorum")
        return
    if not isinstance(signatures, list) or not signatures:
        errors.append(f"{label}: root signatures are required")
        return
    root_ids: list[Any] = []
    valid_principals: set[str] = set()
    valid_materials: set[str] = set()
    expected_fields = (
        ANCHOR_FRESHNESS_ROOT_SIGNATURE_FIELDS
        if require_algorithm
        else ROOT_SIGNATURE_FIELDS
    )
    for number, signature in enumerate(signatures):
        signature_label = f"{label}[{number}]"
        _exact_keys(signature, expected_fields, signature_label, errors)
        if not isinstance(signature, Mapping):
            continue
        root_id = signature.get("rootKeyId")
        root_ids.append(root_id)
        if require_algorithm and signature.get("algorithm") != "Ed25519":
            errors.append(f"{signature_label}.algorithm: expected Ed25519")
        root_key = roots.get(root_id)
        if root_key is None or root_id not in allowed:
            errors.append(f"{signature_label}.rootKeyId: root is not allowed")
            continue
        signed_at = _parse_time(
            signature.get("signedAt"), f"{signature_label}.signedAt", errors
        )
        valid_from = _parse_time(
            root_key.get("notBefore"), f"{signature_label}.root.notBefore", errors
        )
        valid_until = _parse_time(
            root_key.get("notAfter"), f"{signature_label}.root.notAfter", errors
        )
        if (
            signed_at is None
            or valid_from is None
            or valid_until is None
            or not (valid_from <= signed_at < valid_until)
        ):
            errors.append(f"{signature_label}: root key is not valid at signedAt")
            continue
        subject = {
            "rootKeyId": root_id,
            "signedAt": signature.get("signedAt"),
            digest_field: digest,
        }
        try:
            preimage = domain.encode("ascii") + b"\x00" + canonical_json_bytes(subject)
        except (CanonicalizationError, TypeError, ValueError) as exc:
            errors.append(f"{signature_label}: cannot canonicalize root subject: {exc}")
            continue
        if _verify_ed25519(
            root_key.get("publicKeyBase64Url"),
            signature.get("signature"),
            preimage,
            signature_label,
            errors,
        ):
            principal = root_key.get("principalId")
            material = root_key.get("publicKeyBase64Url")
            if isinstance(principal, str):
                valid_principals.add(principal)
            if isinstance(material, str):
                valid_materials.add(material)
    if root_ids != sorted(root_ids, key=canonical_json_bytes) or len(root_ids) != len(
        set(root_ids)
    ):
        errors.append(f"{label}: rootKeyId values must be unique and canonical")
    if min(len(valid_principals), len(valid_materials)) < required:
        errors.append(
            f"{label}: {len(valid_principals)} valid principals/"
            f"{len(valid_materials)} key materials, {required} required"
        )


def _validate_rooted_key_ring(
    key_ring: Mapping[str, Any],
    root_set: Mapping[str, Any],
    label: str,
    errors: list[str],
) -> str | None:
    _validate_key_ring_shape(key_ring, label, errors)
    projection = copy.deepcopy(dict(key_ring))
    projection["rootSignatures"] = []
    projection["keyRingDigest"] = None
    digest = _canonical_digest(projection, f"{label} projection", errors)
    if key_ring.get("keyRingDigest") != digest:
        errors.append(f"{label}.keyRingDigest: canonical projection mismatch")
    if digest is not None:
        _verify_root_digest_quorum(
            root_set,
            key_ring.get("rootSignatures"),
            digest_field="keyRingDigest",
            digest=digest,
            domain="QMAN-DIRECTPATH/TRUST-KEY-RING/V1",
            label=f"{label}.rootSignatures",
            errors=errors,
        )
    return digest


def _validate_trust_key_ring_history(
    history: Mapping[str, Any],
    root_set: Mapping[str, Any],
    current_ring: Mapping[str, Any],
    current_ring_blob: bytes | None,
    evidence_git: _GitView | None,
    root: Path,
    label: str,
    errors: list[str],
) -> dict[int, str]:
    _validate_closed_json_schema_instance(
        history,
        root,
        "contracts/directpath-trust-key-ring-history.schema.json",
        label,
        errors,
    )
    _exact_keys(history, TRUST_KEY_RING_HISTORY_FIELDS, label, errors)
    projection = copy.deepcopy(dict(history))
    projection["historyDigest"] = None
    history_digest = _canonical_digest(projection, f"{label} projection", errors)
    if history.get("historyDigest") != history_digest:
        errors.append(f"{label}.historyDigest: canonical projection mismatch")
    if history.get("rootSetDigest") != root_set.get("rootSetDigest"):
        errors.append(f"{label}.rootSetDigest: pinned root mismatch")
    if history.get("keyRingId") != current_ring.get("keyRingId"):
        errors.append(f"{label}.keyRingId: current ring mismatch")
    if history.get("currentKeyRingSequence") != current_ring.get("keyRingSequence"):
        errors.append(f"{label}.currentKeyRingSequence: current ring mismatch")
    if history.get("currentKeyRingDigest") != current_ring.get("keyRingDigest"):
        errors.append(f"{label}.currentKeyRingDigest: current ring mismatch")
    descriptors = history.get("rings")
    if not isinstance(descriptors, list) or not descriptors:
        errors.append(f"{label}.rings: complete non-empty history is required")
        return {}
    sequences: list[Any] = []
    raw_hashes: set[Any] = set()
    ring_digests: set[Any] = set()
    previous_digest: Any = None
    previous_keys: dict[str, Mapping[str, Any]] = {}
    seen_key_identity: dict[str, tuple[Any, Any]] = {}
    seen_material_identity: dict[str, tuple[Any, Any]] = {}
    permanently_absent: set[str] = set()
    revoked_ids: set[str] = set()
    digest_by_sequence: dict[int, str] = {}
    final_blob: bytes | None = None
    for number, descriptor in enumerate(descriptors):
        ring_label = f"{label}.rings[{number}]"
        _exact_keys(
            descriptor,
            TRUST_KEY_RING_HISTORY_DESCRIPTOR_FIELDS,
            ring_label,
            errors,
        )
        if not isinstance(descriptor, Mapping):
            continue
        sequences.append(descriptor.get("keyRingSequence"))
        for field, seen in (
            ("sha256", raw_hashes),
            ("keyRingDigest", ring_digests),
        ):
            value = descriptor.get(field)
            if not isinstance(value, str):
                errors.append(f"{ring_label}.{field}: expected digest string")
                continue
            if value in seen:
                errors.append(f"{ring_label}.{field}: duplicate history value")
            seen.add(value)
        ring_blob = _typed_artifact_from_git(
            descriptor,
            evidence_git,
            root,
            ring_label,
            errors,
            expected_schema_ref="contracts/directpath-trust-key-ring.schema.json",
            descriptor_fields=TRUST_KEY_RING_HISTORY_DESCRIPTOR_FIELDS,
        )
        ring = (
            _load_json_bytes(ring_blob, ring_label, errors)
            if ring_blob is not None
            else None
        )
        if not isinstance(ring, Mapping):
            continue
        ring_digest = _validate_rooted_key_ring(ring, root_set, ring_label, errors)
        sequence_value = ring.get("keyRingSequence")
        if isinstance(sequence_value, int) and not isinstance(
            sequence_value, bool
        ) and isinstance(ring_digest, str):
            previous_sequence_digest = digest_by_sequence.get(sequence_value)
            if (
                previous_sequence_digest is not None
                and previous_sequence_digest != ring_digest
            ):
                errors.append(
                    f"{ring_label}: sequence {sequence_value} has multiple digests"
                )
            digest_by_sequence[sequence_value] = ring_digest
        mirrored = {
            "keyRingId": ring.get("keyRingId"),
            "keyRingSequence": ring.get("keyRingSequence"),
            "previousKeyRingDigest": ring.get("previousKeyRingDigest"),
            "keyRingDigest": ring.get("keyRingDigest"),
        }
        for field, expected in mirrored.items():
            if descriptor.get(field) != expected:
                errors.append(f"{ring_label}.{field}: parsed ring mismatch")
        if ring.get("keyRingId") != history.get("keyRingId"):
            errors.append(f"{ring_label}.keyRingId: history mismatch")
        if number == 0:
            if ring.get("previousKeyRingDigest") is not None:
                errors.append(f"{ring_label}: genesis previous digest must be null")
        elif ring.get("previousKeyRingDigest") != previous_digest:
            errors.append(f"{ring_label}: previousKeyRingDigest chain break")
        previous_digest = ring_digest

        current_keys = {
            item.get("keyId"): item
            for item in ring.get("keys", [])
            if isinstance(item, Mapping) and isinstance(item.get("keyId"), str)
        }
        reappeared = permanently_absent & set(current_keys)
        if reappeared:
            errors.append(f"{ring_label}: removed keys reappeared {sorted(reappeared)}")
        permanently_absent.update(set(previous_keys) - set(current_keys))
        revoked_values = ring.get("revokedKeyIds")
        current_revoked = {
            item
            for item in revoked_values
            if isinstance(item, str)
        } if isinstance(revoked_values, list) else set()
        if not revoked_ids.issubset(current_revoked):
            errors.append(f"{ring_label}: revokedKeyIds is not monotonic")
        revoked_ids.update(current_revoked)
        for key_id, key in current_keys.items():
            identity = (key.get("principalId"), key.get("publicKeyBase64Url"))
            if key_id in seen_key_identity and seen_key_identity[key_id] != identity:
                errors.append(f"{ring_label}: keyId {key_id!r} changed identity")
            seen_key_identity[key_id] = identity
            material = key.get("publicKeyBase64Url")
            if isinstance(material, str):
                material_identity = (key_id, key.get("principalId"))
                if material in seen_material_identity and seen_material_identity[
                    material
                ] != material_identity:
                    errors.append(f"{ring_label}: Ed25519 material changed identity")
                seen_material_identity[material] = material_identity
            old = previous_keys.get(key_id)
            if isinstance(old, Mapping):
                old_before = _parse_time(
                    old.get("notBefore"), f"{ring_label}.previous.notBefore", errors
                )
                new_before = _parse_time(
                    key.get("notBefore"), f"{ring_label}.current.notBefore", errors
                )
                old_after = _parse_time(
                    old.get("notAfter"), f"{ring_label}.previous.notAfter", errors
                )
                new_after = _parse_time(
                    key.get("notAfter"), f"{ring_label}.current.notAfter", errors
                )
                if old_before is not None and new_before is not None and new_before < old_before:
                    errors.append(f"{ring_label}: key validity begins earlier")
                if old_after is not None and new_after is not None and new_after > old_after:
                    errors.append(f"{ring_label}: key validity was extended")
                old_revoked = old.get("revokedAtOrNull")
                if old_revoked is not None and key.get("revokedAtOrNull") != old_revoked:
                    errors.append(f"{ring_label}: per-key revocation was cleared/changed")
        previous_keys = current_keys
        final_blob = ring_blob
    expected_sequences = list(range(1, len(descriptors) + 1))
    if sequences != expected_sequences or sequences[-1:] != [
        history.get("currentKeyRingSequence")
    ]:
        errors.append(f"{label}.rings: sequences must be the exact contiguous 1..current chain")
    if final_blob is not None and current_ring_blob is not None and final_blob != current_ring_blob:
        errors.append(f"{label}: final history ring bytes differ from current trustKeyRing")
    return digest_by_sequence


def _validate_anchor_freshness_envelope(
    envelope_input: Any,
    verifier_nonce: str | None,
    *,
    anchor_kind: str,
    anchor: Mapping[str, Any],
    anchor_raw: bytes | None,
    anchor_schema_ref: str,
    subject_field: str,
    root_set: Mapping[str, Any],
    root: Path,
    code_git: _GitView | None,
    evidence_git: _GitView | None,
    label: str,
    errors: list[str],
) -> Mapping[str, Any] | None:
    _, envelope = _external_anchor_bytes(
        envelope_input, root, code_git, evidence_git, label, errors
    )
    if not isinstance(envelope, Mapping):
        return None
    _validate_closed_json_schema_instance(
        envelope,
        root,
        "contracts/directpath-anchor-freshness-envelope.schema.json",
        label,
        errors,
    )
    _exact_keys(envelope, ANCHOR_FRESHNESS_FIELDS, label, errors)
    schema_blob = _worktree_bytes(root, anchor_schema_ref, f"{label}.anchorSchema", errors)
    expected = {
        "anchorKind": anchor_kind,
        "authorityId": anchor.get("authorityId"),
        "subjectId": anchor.get(subject_field),
        "anchorBlobSha256": sha256(anchor_raw) if anchor_raw is not None else None,
        "anchorSchemaRef": anchor_schema_ref,
        "anchorSchemaSha256": sha256(schema_blob) if schema_blob is not None else None,
        "anchorDigest": anchor.get("anchorDigest"),
        "anchorVersion": anchor.get("anchorVersion"),
        "resourceVersion": anchor.get("resourceVersion"),
        "verifierNonce": verifier_nonce,
        "trustRootDigest": root_set.get("rootSetDigest"),
    }
    for field, value in expected.items():
        if envelope.get(field) != value:
            errors.append(f"{label}.{field}: live anchor/nonce mismatch")
    if verifier_nonce is None:
        errors.append(f"{label}: independently generated verifier_nonce is required")
    else:
        try:
            decoded_nonce = base64.urlsafe_b64decode(
                verifier_nonce + ("=" * ((-len(verifier_nonce)) % 4))
            )
            canonical_nonce = base64.urlsafe_b64encode(decoded_nonce).decode("ascii").rstrip("=")
            if canonical_nonce != verifier_nonce or len(decoded_nonce) < 16:
                raise ValueError("nonce is non-canonical or below 128 bits")
        except (ValueError, base64.binascii.Error) as exc:
            errors.append(f"{label}.verifierNonce: invalid fresh nonce: {exc}")
    observed = _parse_time(envelope.get("observedAt"), f"{label}.observedAt", errors)
    expires = _parse_time(envelope.get("expiresAt"), f"{label}.expiresAt", errors)
    anchor_updated = _parse_time(
        anchor.get("updatedAt"), f"{label}.anchor.updatedAt", errors
    )
    receipt = anchor.get("receipt")
    receipt_issued = (
        _parse_time(
            receipt.get("issuedAt"), f"{label}.anchor.receipt.issuedAt", errors
        )
        if isinstance(receipt, Mapping)
        else None
    )
    if (
        observed is not None
        and anchor_updated is not None
        and anchor_updated > observed
    ):
        errors.append(f"{label}.observedAt: predates committed anchor update")
    if (
        observed is not None
        and receipt_issued is not None
        and receipt_issued > observed
    ):
        errors.append(f"{label}.observedAt: predates anchor receipt issuance")
    now = _datetime.datetime.now(_datetime.timezone.utc)
    if observed is not None and expires is not None:
        if observed >= expires or (expires - observed).total_seconds() > 300:
            errors.append(f"{label}: freshness window must be positive and at most 300s")
        if not (observed <= now <= expires):
            errors.append(f"{label}: freshness envelope is not live at evaluator time")
    projection = copy.deepcopy(dict(envelope))
    projection["freshnessReceiptDigest"] = None
    projection["rootSignatures"] = []
    receipt_digest = _canonical_digest(projection, f"{label} projection", errors)
    if envelope.get("freshnessReceiptDigest") != receipt_digest:
        errors.append(f"{label}.freshnessReceiptDigest: canonical projection mismatch")
    signatures = envelope.get("rootSignatures")
    if isinstance(signatures, list) and observed is not None and expires is not None:
        for number, signature in enumerate(signatures):
            signed_at = (
                _parse_time(
                    signature.get("signedAt"),
                    f"{label}.rootSignatures[{number}].signedAt",
                    errors,
                )
                if isinstance(signature, Mapping)
                else None
            )
            if signed_at is not None and not (observed <= signed_at <= expires):
                errors.append(f"{label}.rootSignatures[{number}]: outside freshness window")
    if receipt_digest is not None:
        _verify_root_digest_quorum(
            root_set,
            signatures,
            digest_field="freshnessReceiptDigest",
            digest=receipt_digest,
            domain="QMAN-DIRECTPATH/ANCHOR-FRESHNESS/V1",
            label=f"{label}.rootSignatures",
            errors=errors,
            require_algorithm=True,
        )
    return envelope


def _load_trust_context(
    mapping: Mapping[str, Any],
    evidence_git: _GitView | None,
    root: Path,
    errors: list[str],
    *,
    trusted_root_digest: str | None = None,
    external_rollback_anchor: Any | None = None,
    trust_anchor_freshness_envelope: Any | None = None,
    verifier_nonce: str | None = None,
    code_git: _GitView | None = None,
) -> _TrustContext | None:
    policy = mapping.get("trustPolicy")
    if not _exact_keys(
        policy,
        {
            "rootSet",
            "expectedTrustRootDigest",
            "rollbackAnchor",
            "catalogRollbackAnchor",
        },
        "trustPolicy",
        errors,
    ):
        return None
    _is_digest(policy.get("expectedTrustRootDigest"), "trustPolicy.expectedTrustRootDigest", errors)
    if trusted_root_digest is None:
        errors.append(
            "trust bootstrap: independently provisioned trusted_root_digest is required; map trustPolicy is only a claim"
        )
    else:
        _is_digest(trusted_root_digest, "trust bootstrap.trusted_root_digest", errors)
        if policy.get("expectedTrustRootDigest") != trusted_root_digest:
            errors.append(
                "trustPolicy.expectedTrustRootDigest: does not match independently provisioned root digest"
            )
    completion = mapping.get("completionEvidence")
    key_ring_artifact = completion.get("trustKeyRing") if isinstance(completion, Mapping) else None
    key_ring_history_artifact = (
        completion.get("trustKeyRingHistory")
        if isinstance(completion, Mapping)
        else None
    )
    root_blob = _typed_artifact_from_git(
        policy.get("rootSet"),
        evidence_git,
        root,
        "trustPolicy.rootSet",
        errors,
        expected_schema_ref="contracts/directpath-trust-root-set.schema.json",
    )
    anchor_blob = _typed_artifact_from_git(
        policy.get("rollbackAnchor"),
        evidence_git,
        root,
        "trustPolicy.rollbackAnchor",
        errors,
        expected_schema_ref="contracts/directpath-trust-rollback-anchor.schema.json",
    )
    ring_blob = _typed_artifact_from_git(
        key_ring_artifact,
        evidence_git,
        root,
        "completionEvidence.trustKeyRing",
        errors,
        expected_schema_ref="contracts/directpath-trust-key-ring.schema.json",
    )
    history_blob = _typed_artifact_from_git(
        key_ring_history_artifact,
        evidence_git,
        root,
        "completionEvidence.trustKeyRingHistory",
        errors,
        expected_schema_ref=(
            "contracts/directpath-trust-key-ring-history.schema.json"
        ),
    )
    catalog_anchor_artifact = policy.get("catalogRollbackAnchor")
    if catalog_anchor_artifact is not None:
        _typed_artifact_from_git(
            catalog_anchor_artifact,
            evidence_git,
            root,
            "trustPolicy.catalogRollbackAnchor",
            errors,
            expected_schema_ref=(
                "contracts/directpath-catalog-rollback-anchor.schema.json"
            ),
        )
    root_set = _load_json_bytes(root_blob, "trust root set", errors) if root_blob is not None else None
    anchor = _load_json_bytes(anchor_blob, "trust rollback anchor", errors) if anchor_blob is not None else None
    key_ring = _load_json_bytes(ring_blob, "trust key ring", errors) if ring_blob is not None else None
    key_ring_history = (
        _load_json_bytes(history_blob, "trust key-ring history", errors)
        if history_blob is not None
        else None
    )
    if (
        not isinstance(root_set, Mapping)
        or not isinstance(anchor, Mapping)
        or not isinstance(key_ring, Mapping)
        or not isinstance(key_ring_history, Mapping)
    ):
        return None
    _validate_root_set(
        root_set,
        trusted_root_digest if trusted_root_digest is not None else policy.get("expectedTrustRootDigest"),
        "trustRootSet",
        errors,
    )
    _validate_rooted_key_ring(key_ring, root_set, "trustKeyRing", errors)
    history_digests = _validate_trust_key_ring_history(
        key_ring_history,
        root_set,
        key_ring,
        ring_blob,
        evidence_git,
        root,
        "trustKeyRingHistory",
        errors,
    )
    _exact_keys(anchor, ROLLBACK_FIELDS, "trustRollbackAnchor", errors)
    if anchor.get("schemaVersion") != 1:
        errors.append("trustRollbackAnchor.schemaVersion: expected 1")
    if not isinstance(anchor.get("anchorVersion"), int) or isinstance(
        anchor.get("anchorVersion"), bool
    ) or anchor.get("anchorVersion") < 1:
        errors.append("trustRollbackAnchor.anchorVersion: expected positive integer")
    _parse_time(anchor.get("updatedAt"), "trustRollbackAnchor.updatedAt", errors)
    if not isinstance(anchor.get("authorityId"), str) or not anchor.get("authorityId"):
        errors.append("trustRollbackAnchor.authorityId: expected external authority")
    expected_anchor_literals = {
        "recordType": "DIRECTPATH_TRUST_KEY_RING_ROLLBACK_ANCHOR",
        "canonicalProfileId": "CANONICAL-JSON-V1",
        "recordState": "COMMITTED",
    }
    for field, expected in expected_anchor_literals.items():
        if anchor.get(field) != expected:
            errors.append(f"trustRollbackAnchor.{field}: expected {expected!r}")
    _exact_keys(
        anchor.get("casPrecondition"),
        TRUST_ROLLBACK_CAS_FIELDS,
        "trustRollbackAnchor.casPrecondition",
        errors,
    )
    anchor_projection = copy.deepcopy(dict(anchor))
    anchor_projection["anchorDigest"] = None
    anchor_digest = _canonical_digest(
        anchor_projection, "trustRollbackAnchor projection", errors
    )
    if anchor.get("anchorDigest") != anchor_digest:
        errors.append("trustRollbackAnchor.anchorDigest: canonical projection mismatch")
    anchor_version = anchor.get("anchorVersion")
    resource_version = anchor.get("resourceVersion")
    if (
        isinstance(anchor_version, int)
        and not isinstance(anchor_version, bool)
        and isinstance(resource_version, int)
        and not isinstance(resource_version, bool)
        and anchor_version != resource_version
    ):
        errors.append(
            "trustRollbackAnchor: anchorVersion/resourceVersion is unreachable "
            "from the 1/1 genesis with lockstep increments"
        )
    cas = anchor.get("casPrecondition")
    if isinstance(cas, Mapping) and anchor_version == 1:
        if resource_version != 1 or anchor.get("previousAnchorDigestOrNull") is not None:
            errors.append("trustRollbackAnchor: invalid genesis versions/predecessor")
        if any(value is not None for value in cas.values()):
            errors.append("trustRollbackAnchor.casPrecondition: genesis requires all null")
    elif isinstance(cas, Mapping) and isinstance(anchor_version, int):
        expected_anchor_version = cas.get("expectedAnchorVersionOrNull")
        if (
            not isinstance(expected_anchor_version, int)
            or isinstance(expected_anchor_version, bool)
            or anchor_version != expected_anchor_version + 1
        ):
            errors.append("trustRollbackAnchor.anchorVersion: CAS successor must increment by one")
        expected_resource_version = cas.get("expectedResourceVersionOrNull")
        if (
            not isinstance(expected_resource_version, int)
            or isinstance(expected_resource_version, bool)
            or not isinstance(resource_version, int)
            or isinstance(resource_version, bool)
            or resource_version != expected_resource_version + 1
        ):
            errors.append("trustRollbackAnchor.resourceVersion: CAS successor must increment by one")
        if anchor.get("previousAnchorDigestOrNull") != cas.get(
            "expectedAnchorDigestOrNull"
        ):
            errors.append("trustRollbackAnchor.previousAnchorDigestOrNull: CAS mismatch")
        expected_minimum = cas.get("expectedMinimumSequenceOrNull")
        if isinstance(expected_minimum, int):
            expected_predecessor_digest = history_digests.get(expected_minimum)
            if expected_predecessor_digest is None:
                errors.append(
                    "trustRollbackAnchor.casPrecondition.expectedMinimumSequenceOrNull: "
                    "does not resolve the verified key-ring history"
                )
            elif cas.get(
                "expectedAcceptedKeyRingDigestOrNull"
            ) != expected_predecessor_digest:
                errors.append(
                    "trustRollbackAnchor.casPrecondition."
                    "expectedAcceptedKeyRingDigestOrNull: predecessor history mismatch"
                )
            if anchor.get("minimumSequence", 0) < expected_minimum:
                errors.append("trustRollbackAnchor.minimumSequence: rollback")
            if (
                anchor.get("minimumSequence") == expected_minimum
                and anchor.get("acceptedKeyRingDigest")
                != cas.get("expectedAcceptedKeyRingDigestOrNull")
            ):
                errors.append("trustRollbackAnchor: same-sequence digest equivocation")
    external_anchor_document: Mapping[str, Any] | None = None
    external_anchor_bytes: bytes | None = None
    if external_rollback_anchor is None:
        errors.append(
            "trust bootstrap: independently supplied external_rollback_anchor is required; target blob is only a receipt claim"
        )
    else:
        external_anchor_bytes, external_anchor_document = _external_anchor_bytes(
            external_rollback_anchor,
            root,
            code_git,
            evidence_git,
            "trust bootstrap.external_rollback_anchor",
            errors,
        )
    if external_anchor_document is not None:
        _exact_keys(
            external_anchor_document,
            ROLLBACK_FIELDS,
            "trust bootstrap.external_rollback_anchor",
            errors,
        )
        if (
            external_anchor_bytes is not None
            and anchor_blob is not None
            and external_anchor_bytes != anchor_blob
        ):
            errors.append(
                "trustPolicy.rollbackAnchor: target receipt raw bytes do not equal "
                "the independently supplied monotonic anchor state"
            )
    ring_projection = copy.deepcopy(dict(key_ring))
    ring_projection["rootSignatures"] = []
    ring_projection["keyRingDigest"] = None
    projection_bytes: bytes | None = None
    try:
        projection_bytes = canonical_json_bytes(ring_projection)
        ring_digest = sha256(projection_bytes)
        if key_ring.get("keyRingDigest") != ring_digest:
            errors.append(
                f"trustKeyRing.keyRingDigest: declared {key_ring.get('keyRingDigest')}, actual {ring_digest}"
            )
    except (CanonicalizationError, TypeError, ValueError) as exc:
        errors.append(f"trustKeyRing: cannot canonicalize signing projection: {exc}")
        ring_digest = None
    if anchor.get("keyRingId") != key_ring.get("keyRingId"):
        errors.append("trustRollbackAnchor.keyRingId: does not match key ring")
    minimum = anchor.get("minimumSequence")
    sequence = key_ring.get("keyRingSequence")
    if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 1:
        errors.append("trustRollbackAnchor.minimumSequence: expected positive integer")
    elif isinstance(sequence, int) and sequence != minimum:
        errors.append("trustKeyRing.keyRingSequence: must equal external accepted sequence")
    if ring_digest is not None and anchor.get("acceptedKeyRingDigest") != ring_digest:
        errors.append("trustRollbackAnchor.acceptedKeyRingDigest: does not accept this exact key ring")
    roots = {
        item.get("keyId"): item
        for item in root_set.get("keys", [])
        if isinstance(item, Mapping) and isinstance(item.get("keyId"), str)
    }
    root_policy = root_set.get("verificationPolicy")
    allowed_root_ids = (
        set(root_policy.get("allowedKeyIds", []))
        if isinstance(root_policy, Mapping)
        and isinstance(root_policy.get("allowedKeyIds"), list)
        else set()
    )
    required_signatures = (
        root_policy.get("requiredSignatures")
        if isinstance(root_policy, Mapping)
        else None
    )
    allowed_root_principals = {
        roots[key_id].get("principalId")
        for key_id in allowed_root_ids
        if key_id in roots and isinstance(roots[key_id].get("principalId"), str)
    }
    if (
        not isinstance(required_signatures, int)
        or isinstance(required_signatures, bool)
        or required_signatures < 1
        or required_signatures > len(allowed_root_principals)
    ):
        errors.append(
            "trustRootSet.verificationPolicy: no valid externally pinned signature quorum"
        )
        required_signatures = len(roots) + 1
    valid_root_principals: set[str] = set()
    if projection_bytes is not None and ring_digest is not None:
        for index, signature in enumerate(key_ring.get("rootSignatures", [])):
            if not isinstance(signature, Mapping):
                continue
            label = f"trustKeyRing.rootSignatures[{index}]"
            root_key = roots.get(signature.get("rootKeyId"))
            if root_key is None:
                errors.append(f"{label}.rootKeyId: unknown offline root key")
                continue
            if signature.get("rootKeyId") not in allowed_root_ids:
                errors.append(
                    f"{label}.rootKeyId: key is outside the externally pinned root policy"
                )
                continue
            signed_at = _parse_time(signature.get("signedAt"), f"{label}.signedAt", errors)
            not_before = _parse_time(root_key.get("notBefore"), f"{label}.root.notBefore", errors)
            not_after = _parse_time(root_key.get("notAfter"), f"{label}.root.notAfter", errors)
            if signed_at is not None and not_before is not None and not_after is not None:
                if not (not_before <= signed_at < not_after):
                    errors.append(f"{label}: root key was not valid at signedAt")
                    continue
            signature_subject = {
                "rootKeyId": signature.get("rootKeyId"),
                "signedAt": signature.get("signedAt"),
                "keyRingDigest": ring_digest,
            }
            try:
                signature_preimage = (
                    b"QMAN-DIRECTPATH/TRUST-KEY-RING/V1\x00"
                    + canonical_json_bytes(signature_subject)
                )
            except (CanonicalizationError, TypeError, ValueError) as exc:
                errors.append(f"{label}: cannot canonicalize signed subject: {exc}")
                continue
            if _verify_ed25519(
                root_key.get("publicKeyBase64Url"),
                signature.get("signature"),
                signature_preimage,
                label,
                errors,
            ):
                principal_id = root_key.get("principalId")
                if isinstance(principal_id, str):
                    valid_root_principals.add(principal_id)
    if len(valid_root_principals) < required_signatures:
        errors.append(
            "trustKeyRing.rootSignatures: "
            f"{len(valid_root_principals)} valid unique root principals, "
            f"{required_signatures} required"
        )
    freshness = _validate_anchor_freshness_envelope(
        trust_anchor_freshness_envelope,
        verifier_nonce,
        anchor_kind="TRUST_KEY_RING",
        anchor=(
            external_anchor_document
            if isinstance(external_anchor_document, Mapping)
            else anchor
        ),
        anchor_raw=(
            external_anchor_bytes
            if external_anchor_bytes is not None
            else anchor_blob
        ),
        anchor_schema_ref="contracts/directpath-trust-rollback-anchor.schema.json",
        subject_field="keyRingId",
        root_set=root_set,
        root=root,
        code_git=code_git,
        evidence_git=evidence_git,
        label="trust bootstrap.anchorFreshness",
        errors=errors,
    )
    return _TrustContext(
        root_set,
        key_ring,
        anchor,
        key_ring_history=key_ring_history,
        trust_anchor_freshness=freshness,
    )


def _verify_signed_envelope(
    document: Mapping[str, Any],
    *,
    digest_field: str,
    signature_field: str,
    signer_field: str,
    signed_time_field: str,
    domain: str,
    required_role: str,
    trust: _TrustContext | None,
    label: str,
    errors: list[str],
) -> None:
    if trust is None:
        errors.append(f"{label}: authenticated trust context is unavailable")
        return
    if digest_field not in document or signature_field not in document:
        errors.append(f"{label}: missing signed-envelope digest/signature fields")
        return
    projection = copy.deepcopy(dict(document))
    projection[digest_field] = None
    projection[signature_field] = None
    try:
        projection_bytes = canonical_json_bytes(projection)
    except (CanonicalizationError, TypeError, ValueError) as exc:
        errors.append(f"{label}: cannot canonicalize signed projection: {exc}")
        return
    digest = sha256(projection_bytes)
    if document.get(digest_field) != digest:
        errors.append(
            f"{label}.{digest_field}: declared {document.get(digest_field)}, actual {digest}"
        )
    key_id = document.get(signer_field)
    key = trust.keys.get(key_id) if isinstance(key_id, str) else None
    if key is None:
        errors.append(f"{label}.{signer_field}: unknown signer key {key_id!r}")
        return
    roles = key.get("roles", [])
    if not isinstance(roles, list) or required_role not in roles:
        errors.append(f"{label}: signer key lacks required role {required_role}")
    ring_version = document.get("keyRingVersion")
    if ring_version != trust.key_ring.get("keyRingSequence"):
        errors.append(f"{label}.keyRingVersion: does not match authenticated key ring")
    if "trustKeyRingDigest" in document and document.get("trustKeyRingDigest") != trust.key_ring.get("keyRingDigest"):
        errors.append(f"{label}.trustKeyRingDigest: does not match authenticated key ring")
    signed_at = _parse_time(document.get(signed_time_field), f"{label}.{signed_time_field}", errors)
    key_before = _parse_time(key.get("notBefore"), f"{label}.signer.notBefore", errors)
    key_after = _parse_time(key.get("notAfter"), f"{label}.signer.notAfter", errors)
    ring_before = _parse_time(trust.key_ring.get("notBefore"), f"{label}.ring.notBefore", errors)
    ring_after = _parse_time(trust.key_ring.get("expiresAt"), f"{label}.ring.expiresAt", errors)
    if signed_at is not None:
        if key_before is not None and key_after is not None and not (key_before <= signed_at < key_after):
            errors.append(f"{label}: signer key was not valid at signed time")
        if ring_before is not None and ring_after is not None and not (ring_before <= signed_at < ring_after):
            errors.append(f"{label}: key ring was not valid at signed time")
        revoked_at_value = key.get("revokedAtOrNull")
        if revoked_at_value is not None:
            revoked_at = _parse_time(revoked_at_value, f"{label}.signer.revokedAt", errors)
            if revoked_at is not None and signed_at >= revoked_at:
                errors.append(f"{label}: signer key was revoked at signed time")
    if key_id in trust.key_ring.get("revokedKeyIds", []):
        errors.append(f"{label}: signer key is in the key-ring revocation set")
    preimage = domain.encode("ascii") + b"\x00" + projection_bytes
    _verify_ed25519(
        key.get("publicKeyBase64Url"), document.get(signature_field), preimage, label, errors
    )


MAP_FIELDS = {
    "schemaVersion",
    "mapId",
    "mappingCoreId",
    "mapDigest",
    "scenarioBindingDigest",
    "sourceContract",
    "targetRepository",
    "evidenceRepository",
    "artifactTopology",
    "trustPolicy",
    "statusAxes",
    "mappings",
    "completionEvidence",
    "approvals",
}
SOURCE_CONTRACT_FIELDS = {"path", "contractId", "revision", "sha256"}
TARGET_REPOSITORY_FIELDS = {
    "repositoryId",
    "repositoryLocation",
    "objectFormat",
    "commit",
    "branch",
    "language",
    "buildCommand",
    "testCommand",
}
EVIDENCE_REPOSITORY_FIELDS = {
    "repositoryId",
    "repositoryLocation",
    "objectFormat",
    "commit",
    "artifactRoot",
}
ARTIFACT_TOPOLOGY_FIELDS = {
    "graph",
    "mappingCoreStorage",
    "catalogAnchorStorage",
    "finalMapStorage",
    "selfReferencePolicy",
}
STATUS_FIELDS = {"PORTABLE_SPEC_READY", "TARGET_CODE_MAPPED", "PRODUCT_IMPLEMENTED", "QUALIFIED"}
MAPPING_FIELDS = {
    "contractItemId",
    "kind",
    "verificationRequirementDigest",
    "releaseTrack",
    "mappingStatus",
    "disposition",
    "implementationStatus",
    "targetBindings",
    "targetTestBindings",
    "transitionExecutionBinding",
    "conflict",
    "deferDecision",
    "notes",
}
TARGET_BINDING_FIELDS = {
    "service",
    "path",
    "symbol",
    "symbolKind",
    "symbolResolver",
    "symbolLocator",
    "hashScope",
    "interfaceHash",
    "symbolSemanticHash",
    "resolverEvidencePath",
    "resolverEvidenceSha256",
}
TEST_BINDING_FIELDS = {
    "contractItemId",
    "testFileRepositoryAuthority",
    "path",
    "symbol",
    "testFileSha256",
    "testFileHashScope",
    "scenarioPath",
    "scenarioId",
    "scenarioSha256",
    "scenarioHashScope",
    "scenarioRepositoryAuthority",
    "caseIds",
    "targetRepositoryCommit",
    "evidenceRepositoryCommit",
    "executionEvidenceIndexRecordSha256",
}
CONFLICT_FIELDS = {"description", "safetyImpact", "resolution", "approvalEvidenceHash"}
DEFER_FIELDS = {
    "authorityPath",
    "authoritySha256",
    "authorityDecisionId",
    "decision",
    "releaseTrack",
    "authorizationModel",
    "approvalEvidenceHash",
}
COMPLETION_FIELDS = {
    "mappingCoverageReport",
    "implementationTestReport",
    "qualificationEvidenceIndex",
    "conflictRegister",
    "trustKeyRing",
    "trustKeyRingHistory",
}
COMPLETION_SCHEMA_REFS = {
    "mappingCoverageReport": (
        "contracts/directpath-integration-report.schema.json#/$defs/mappingCoverageReport"
    ),
    "implementationTestReport": (
        "contracts/directpath-integration-report.schema.json#/$defs/implementationTestReport"
    ),
    "qualificationEvidenceIndex": (
        "contracts/directpath-qualification-release-index.schema.json"
    ),
    "conflictRegister": (
        "contracts/directpath-integration-report.schema.json#/$defs/conflictRegister"
    ),
    "trustKeyRing": "contracts/directpath-trust-key-ring.schema.json",
    "trustKeyRingHistory": (
        "contracts/directpath-trust-key-ring-history.schema.json"
    ),
}
INTEGRATION_REPORT_FIELDS = {
    "schemaVersion",
    "reportType",
    "canonicalProfileId",
    "publicationState",
    "reportId",
    "reportSequence",
    "portableContract",
    "targetCodeRevision",
    "mappingCore",
    "generatedAt",
    "evidenceContentHashes",
    "limitations",
    "keyRingVersion",
    "trustKeyRingDigest",
    "signerRole",
    "signerKeyId",
    "reportDigest",
    "signature",
}
INTEGRATION_REPORT_TYPE_FIELDS = {
    "MAPPING_COVERAGE_REPORT": {
        "status",
        "requiredContractItemIds",
        "itemResults",
        "summary",
    },
    "CONFLICT_REGISTER": {"status", "conflicts"},
    "IMPLEMENTATION_TEST_REPORT": {
        "status",
        "testPlanDigest",
        "buildResult",
        "testResults",
        "platformProfileIds",
        "caseCompletionRecords",
        "summary",
    },
}
INTEGRATION_REPORT_ROLES = {
    "MAPPING_COVERAGE_REPORT": "TARGET_ARCHITECT",
    "CONFLICT_REGISTER": "SECURITY",
    "IMPLEMENTATION_TEST_REPORT": "TEST",
}
INTEGRATION_PORTABLE_CONTRACT_FIELDS = {"contractId", "revision", "sha256"}
INTEGRATION_TARGET_CODE_FIELDS = {
    "repositoryId",
    "repositoryLocatorDigest",
    "objectFormat",
    "revision",
}
INTEGRATION_MAPPING_CORE_FIELDS = {"mappingCoreId", "mappingCoreDigest"}
INTEGRATION_EVIDENCE_CONTENT_FIELDS = {
    "artifactRole",
    "path",
    "mediaType",
    "sha256",
}
MAPPING_COVERAGE_ITEM_FIELDS = {
    "contractItemId",
    "kind",
    "releaseTrack",
    "disposition",
    "mappingEntryDigestOrNull",
    "deferDecisionDigestOrNull",
}
MAPPING_COVERAGE_SUMMARY_FIELDS = {
    "requiredCount",
    "boundCount",
    "authorizedDeferredCount",
    "unmappedCount",
    "conflictCount",
}
CONFLICT_REPORT_ITEM_FIELDS = {
    "conflictId",
    "contractItemIds",
    "severity",
    "state",
    "description",
    "discoveredAt",
    "resolutionOrNull",
    "decisionDigestOrNull",
}
IMPLEMENTATION_TEST_RESULT_FIELDS = {
    "testBindingId",
    "scenarioId",
    "scenarioSha256",
    "scenarioRunId",
    "contractItemIds",
    "result",
    "startedAt",
    "completedAt",
    "executionEvidenceIndexRecordSha256OrNull",
}
IMPLEMENTATION_TEST_SUMMARY_FIELDS = {
    "requiredCount",
    "passedCount",
    "failedCount",
    "notExecutedCount",
    "invalidEvidenceCount",
}
IMPLEMENTATION_CASE_COMPLETION_DESCRIPTOR_FIELDS = {
    "caseId",
    "targetCommit",
    "mappingCoreId",
    "platformProfileId",
    "scope",
    "sourceCaseStatus",
    "caseContractDigest",
    "caseContractRegistryDigest",
    "portableContractSha256",
    "path",
    "sha256",
    "completionDigest",
    "schemaRef",
    "schemaSha256",
    "evidenceGrade",
}
APPROVAL_FIELDS = {
    "schemaVersion",
    "role",
    "identity",
    "decision",
    "decidedAt",
    "evidenceHash",
    "keyRingVersion",
    "keyId",
    "trustKeyRingDigest",
    "approvalDigest",
    "signature",
}
SYMBOL_INDEX_FIELDS = {
    "schemaVersion",
    "indexId",
    "targetRepositoryCommit",
    "generator",
    "entries",
    "issuedAt",
    "keyRingVersion",
    "signerKeyId",
    "indexDigest",
    "signature",
}
SYMBOL_GENERATOR_FIELDS = {"tool", "version", "binarySha256", "configurationSha256"}
SYMBOL_ENTRY_FIELDS = {
    "service",
    "path",
    "symbol",
    "symbolKind",
    "symbolResolver",
    "symbolLocator",
    "sourceBlobSha256",
    "symbolSemanticHash",
}
TRANSITION_BINDING_FIELDS = {
    "fsmId",
    "fromState",
    "concreteFromStates",
    "toState",
    "orderedOperations",
    "intentJournal",
    "expectedVersionFields",
    "sameTransactionWriteEntityIds",
    "successAssignedIdEffect",
    "outboxEventTypes",
    "successAuthoritativeState",
    "failureOutcomes",
    "compensationTransitionIds",
    "crashTestScenarioIds",
    "bindingDigest",
}
FAILURE_OUTCOME_FIELDS = {
    "operationId",
    "reasonCode",
    "authoritativeState",
    "leaseClaimEffect",
    "assignedIdEffect",
    "releaseGuardEffect",
    "quarantineScope",
    "retryPolicy",
    "compensationTransitionIds",
}
ORDERED_OPERATION_FIELDS = {
    "sequence",
    "operationId",
    "logicalActorPortId",
    "executionPhase",
    "requiredLeaseTypeOrNull",
    "requiredReleaseGuard",
}
INTENT_JOURNAL_FIELDS = {
    "journalEntityId",
    "intentBeforeOperationSequence",
    "intentState",
    "fsyncRequired",
}


OPERATION_LEASE_TYPES = {
    "OWNER_TRANSITION",
    "ASSIGNMENT_PREPARE",
    "RELEASE",
    "RELOCATION_HANDOFF",
    "QUARANTINE_REMEDIATION",
}

# This is the exact operation set whose REQUEST envelope is required by the
# normative operation-envelope schema to carry an OperationLeaseCapability.
# Keeping the registry here deliberate and closed prevents a mapper from
# labelling a real side effect as OBSERVATION merely to make the authority
# disappear.
OPERATION_LEASE_REQUIRED = {
    "OP-EXECUTE-ASSIGNMENT",
    "OP-RECONCILE-ASSIGNMENT",
    "OP-APPLY-OWNER-ACTIVATION",
    "OP-RECONCILE-OWNER-ACTIVATION",
    "OP-CAS-RESERVE-BUNDLES",
    "OP-CAS-TRANSITION-AGGREGATES",
    "OP-CAS-CANCEL-UNSTARTED-RESERVATION",
    "OP-CAS-REVOKE-LEASE",
    "OP-PREPARE-HOST-BUNDLE",
    "OP-TEARDOWN-HOST-BUNDLE",
    "OP-RECONCILE-HOST",
    "OP-MATERIALIZE-BACKEND-GRANT",
    "OP-RELEASE-BACKEND-GRANT",
    "OP-SPAWN-QEMU",
    "OP-STOP-QEMU",
    "OP-ACQUIRE-RELEASE-OWNERSHIP-GUARD",
    "OP-PROVE-CLEAN-RELEASE",
    "OP-QUARANTINE-BUNDLE",
    "OP-REMEDIATE-QUARANTINE",
    "OP-EXECUTE-COLD-RELOCATION",
}

RELEASE_GUARD_REQUIRED_OPERATIONS = {
    "OP-STOP-QEMU",
    "OP-TEARDOWN-HOST-BUNDLE",
    "OP-RELEASE-BACKEND-GRANT",
    "OP-PROVE-CLEAN-RELEASE",
    "OP-CAS-REVOKE-LEASE",
}

FIXED_OPERATION_LEASE_TYPES = {
    "OP-APPLY-OWNER-ACTIVATION": "OWNER_TRANSITION",
    "OP-RECONCILE-OWNER-ACTIVATION": "OWNER_TRANSITION",
    "OP-ACQUIRE-RELEASE-OWNERSHIP-GUARD": "RELEASE",
    "OP-STOP-QEMU": "RELEASE",
    "OP-TEARDOWN-HOST-BUNDLE": "RELEASE",
    "OP-RELEASE-BACKEND-GRANT": "RELEASE",
    "OP-PROVE-CLEAN-RELEASE": "RELEASE",
    "OP-CAS-REVOKE-LEASE": "RELEASE",
    "OP-REMEDIATE-QUARANTINE": "QUARANTINE_REMEDIATION",
    "OP-EXECUTE-COLD-RELOCATION": "RELOCATION_HANDOFF",
}

# The Assignment FSM changes authority at the rollback/release boundary.  In
# particular OP-EXECUTE-ASSIGNMENT is ASSIGNMENT_PREPARE on the forward path,
# but RELEASE when it is reused to drive PREPARING -> ROLLING_BACK.
ASSIGNMENT_RELEASE_TRANSITIONS = {
    "TR-RUN-PREPARING-ROLLING-BACK",
    "TR-RUN-ATTACHED-RELEASING",
    "TR-RUN-RELEASING-FREE",
    "TR-RUN-ROLLBACK-FREE",
    "TR-RUN-ROLLBACK-QUARANTINED",
    "TR-RUN-RELEASING-QUARANTINED",
}

# These relocation transitions atomically commit source/target cleanup while a
# RELEASE authority owns the affected assignment.  Other relocation workflow
# operations remain under RELOCATION_HANDOFF; fixed release operations above
# always remain RELEASE regardless of the FSM.
RELOCATION_RELEASE_COMMIT_TRANSITIONS = {
    "TR-RELOCATE-SOURCE-STOP-RELEASING",
    "TR-RELOCATE-SOURCE-RELEASING-TARGET-SOLVE",
    "TR-RELOCATE-TARGET-ATTACHING-ROLLING-BACK",
    "TR-RELOCATE-TARGET-ROLLBACK-STOPPED-UNSAT",
}

RELEASE_GUARDED_CAS_TRANSITIONS = {
    "TR-RUN-PREPARING-ROLLING-BACK",
    "TR-RUN-RELEASING-FREE",
    "TR-RUN-ROLLBACK-FREE",
    "TR-RUN-ROLLBACK-QUARANTINED",
    "TR-RUN-RELEASING-QUARANTINED",
    "TR-RELOCATE-SOURCE-STOP-RELEASING",
    "TR-RELOCATE-SOURCE-RELEASING-TARGET-SOLVE",
    "TR-RELOCATE-TARGET-ATTACHING-ROLLING-BACK",
    "TR-RELOCATE-TARGET-ROLLBACK-STOPPED-UNSAT",
}

CLEANUP_FAILURE_QUARANTINE_TRANSITIONS = {
    "TR-RUN-ROLLBACK-QUARANTINED",
    "TR-RUN-RELEASING-QUARANTINED",
    "TR-RELOCATE-SOURCE-CLEANUP-QUARANTINED",
}


def _expected_operation_lease_type(
    operation_id: Any,
    transition: Mapping[str, Any],
    machine: Mapping[str, Any],
    execution_phase: Any,
) -> str | None:
    """Derive the one legal typed authority for an ordered operation.

    The result is contextual: the same operation may be used by preparation,
    release, or relocation workflows.  This function therefore uses the
    normative FSM and transition identity, not a caller-supplied phase alone.
    """

    if not isinstance(operation_id, str):
        return None
    if (
        transition.get("id") == "TR-RELOCATE-SOURCE-CLEANUP-QUARANTINED"
        and operation_id in {"OP-QUARANTINE-BUNDLE", "OP-EXECUTE-COLD-RELOCATION"}
    ):
        return "RELEASE"
    fixed = FIXED_OPERATION_LEASE_TYPES.get(operation_id)
    if fixed is not None:
        return fixed
    requires_lease = operation_id in OPERATION_LEASE_REQUIRED or execution_phase in {
        "HOST_SIDE_EFFECT",
        "EXTERNAL_PROCESS",
    }
    if not requires_lease:
        return None
    machine_id = machine.get("id")
    transition_id = transition.get("id")
    if machine_id == "FSM-OWNER-ACTIVATION":
        return "OWNER_TRANSITION"
    if machine_id == "FSM-ASSIGNMENT":
        if transition_id in ASSIGNMENT_RELEASE_TRANSITIONS:
            return "RELEASE"
        return "ASSIGNMENT_PREPARE"
    if machine_id == "FSM-COLD-RELOCATION":
        if (
            transition_id in RELOCATION_RELEASE_COMMIT_TRANSITIONS
            and operation_id == "OP-CAS-TRANSITION-AGGREGATES"
        ):
            return "RELEASE"
        return "RELOCATION_HANDOFF"
    if machine_id == "FSM-QUARANTINE-REMEDIATION":
        return "QUARANTINE_REMEDIATION"
    return None


def _expected_operation_release_guard(
    operation_id: Any,
    transition: Mapping[str, Any],
) -> bool:
    """Return whether this exact operation context consumes the release guard."""

    if operation_id in RELEASE_GUARD_REQUIRED_OPERATIONS:
        return True
    transition_id = transition.get("id")
    if (
        operation_id == "OP-CAS-TRANSITION-AGGREGATES"
        and transition_id in RELEASE_GUARDED_CAS_TRANSITIONS
    ):
        return True
    if (
        operation_id == "OP-EXECUTE-ASSIGNMENT"
        and transition_id == "TR-RUN-PREPARING-ROLLING-BACK"
    ):
        return True
    if (
        transition_id == "TR-RELOCATE-SOURCE-CLEANUP-QUARANTINED"
        and operation_id == "OP-EXECUTE-COLD-RELOCATION"
    ):
        return True
    return (
        operation_id == "OP-QUARANTINE-BUNDLE"
        and transition_id in CLEANUP_FAILURE_QUARANTINE_TRANSITIONS
    )


def _scenario_binding_projection(mapping: Mapping[str, Any]) -> dict[str, Any]:
    projection = copy.deepcopy(dict(mapping))
    projection["mapDigest"] = None
    projection["scenarioBindingDigest"] = None
    projection["evidenceRepository"] = None
    projection["approvals"] = []
    trust_policy = projection.get("trustPolicy")
    if isinstance(trust_policy, dict):
        # The supported-catalog anchor is created only after qualification
        # records/E4/catalog have already bound M.  Keeping it in M would form
        # M -> records -> catalog -> anchor -> M, an unconstructable fixed point.
        trust_policy["catalogRollbackAnchor"] = None
    projection["statusAxes"] = {
        "PORTABLE_SPEC_READY": True,
        "TARGET_CODE_MAPPED": True,
        "PRODUCT_IMPLEMENTED": False,
        "QUALIFIED": False,
    }
    completion = projection.get("completionEvidence")
    if isinstance(completion, Mapping):
        projection["completionEvidence"] = {field: None for field in completion}
    for item in projection.get("mappings", []):
        if not isinstance(item, dict):
            continue
        item["targetTestBindings"] = []
        if item.get("releaseTrack") == "CURRENT_RELEASE_REQUIRED":
            item["implementationStatus"] = "NOT_STARTED"
        elif item.get("mappingStatus") == "DEFERRED":
            item["implementationStatus"] = "NOT_APPLICABLE_CURRENT_RELEASE"
    return projection


def _validate_report_evidence_content(
    value: Any,
    evidence_git: _GitView | None,
    report_descriptor: Mapping[str, Any],
    report: Mapping[str, Any],
    label: str,
    errors: list[str],
) -> dict[str, set[str]]:
    """Validate immutable report leaves and return their hashes grouped by role."""

    if not isinstance(value, list) or not value:
        errors.append(f"{label}.evidenceContentHashes: expected non-empty array")
        return {}
    allowed_roles = {
        "MAPPING_ENTRY_SET",
        "TARGET_SYMBOL_INDEX",
        "RESOLVER_EVIDENCE",
        "ACCEPTANCE_SCENARIO",
        "EXECUTION_EVIDENCE_INDEX",
        "CASE_COMPLETION_RECORD",
        "TEST_LOG",
        "BUILD_LOG",
        "CONFLICT_DECISION",
        "TOOL_MANIFEST",
    }
    allowed_media = {"application/json", "application/jsonl", "text/plain"}
    order: list[bytes] = []
    seen_paths: set[str] = set()
    seen_digests: set[str] = set()
    hashes_by_role: dict[str, set[str]] = {}
    for index, item in enumerate(value):
        item_label = f"{label}.evidenceContentHashes[{index}]"
        _exact_keys(item, INTEGRATION_EVIDENCE_CONTENT_FIELDS, item_label, errors)
        if not isinstance(item, Mapping):
            continue
        role = item.get("artifactRole")
        path = _safe_relative_path(item.get("path"), f"{item_label}.path", errors)
        digest = item.get("sha256")
        if role not in allowed_roles:
            errors.append(f"{item_label}.artifactRole: unknown closed artifact role")
        if item.get("mediaType") not in allowed_media:
            errors.append(f"{item_label}.mediaType: unsupported media type")
        _is_digest(digest, f"{item_label}.sha256", errors, nonzero=True)
        try:
            order.append(canonical_json_bytes([role, path, digest]))
        except (CanonicalizationError, TypeError, ValueError) as exc:
            errors.append(f"{item_label}: invalid canonical order key: {exc}")
        if isinstance(path, str):
            if path in seen_paths:
                errors.append(f"{item_label}.path: duplicate evidence locator")
            seen_paths.add(path)
            if path == report_descriptor.get("path"):
                errors.append(f"{item_label}: a report cannot list itself as evidence")
        if isinstance(digest, str):
            if digest in seen_digests:
                errors.append(f"{item_label}.sha256: duplicate evidence subject is ambiguous")
            seen_digests.add(digest)
            if digest == report_descriptor.get("sha256"):
                errors.append(f"{item_label}: a report cannot hash itself as evidence")
            if isinstance(role, str):
                hashes_by_role.setdefault(role, set()).add(digest)
        blob = (
            evidence_git.blob(path, f"{item_label}.path", errors)
            if evidence_git is not None and path is not None
            else None
        )
        if evidence_git is None:
            errors.append(f"{item_label}: pinned evidence E is unavailable")
        _check_blob_hash(blob, digest, item_label, errors)
        if blob is not None:
            forbidden_claims = (
                report_descriptor.get("sha256"),
                report.get("reportDigest"),
                report.get("signature"),
            )
            embedded_claim = next(
                (
                    claim
                    for claim in forbidden_claims
                    if isinstance(claim, str)
                    and claim
                    and claim.isascii()
                    and claim.encode("ascii") in blob
                ),
                None,
            )
            if embedded_claim is not None:
                errors.append(
                    f"{item_label}: evidence leaf embeds its containing report "
                    "identity/signature and creates a backward edge"
                )
    if order != sorted(order) or len(order) != len(set(order)):
        errors.append(
            f"{label}.evidenceContentHashes: must be unique and canonically sorted "
            "by [artifactRole,path,sha256]"
        )
    return hashes_by_role


def _validate_mapping_coverage_report(
    report: Mapping[str, Any],
    mapping: Mapping[str, Any],
    label: str,
    errors: list[str],
) -> None:
    core = _scenario_binding_projection(mapping)
    core_mappings = core.get("mappings", [])
    if not isinstance(core_mappings, list):
        errors.append(f"{label}: mapping-core projection lacks mappings")
        return
    expected_rows: list[dict[str, Any]] = []
    dispositions = {
        "BOUND": "BOUND",
        "DEFERRED": "AUTHORIZED_DEFERRED",
        "UNMAPPED": "UNMAPPED",
        "CONFLICT": "CONFLICT",
    }
    for index, item in enumerate(core_mappings):
        if not isinstance(item, Mapping):
            errors.append(f"{label}: mapping-core entry {index} is not an object")
            continue
        status = item.get("mappingStatus")
        mapping_digest = (
            _canonical_digest(item, f"{label}.M.mappings[{index}]", errors)
            if status == "BOUND"
            else None
        )
        defer_decision = item.get("deferDecision")
        defer_digest = (
            _canonical_digest(
                defer_decision,
                f"{label}.M.mappings[{index}].deferDecision",
                errors,
            )
            if status == "DEFERRED" and defer_decision is not None
            else None
        )
        expected_rows.append(
            {
                "contractItemId": item.get("contractItemId"),
                "kind": item.get("kind"),
                "releaseTrack": item.get("releaseTrack"),
                "disposition": dispositions.get(status),
                "mappingEntryDigestOrNull": mapping_digest,
                "deferDecisionDigestOrNull": defer_digest,
            }
        )
    expected_rows.sort(key=lambda item: canonical_json_bytes(item["contractItemId"]))
    expected_ids = [item["contractItemId"] for item in expected_rows]
    required_ids = _unique_strings(
        report.get("requiredContractItemIds"),
        f"{label}.requiredContractItemIds",
        errors,
    )
    _require_canonical_set_order(
        report.get("requiredContractItemIds"),
        f"{label}.requiredContractItemIds",
        errors,
    )
    if required_ids != expected_ids:
        errors.append(
            f"{label}.requiredContractItemIds: must exactly equal all M mapping obligations"
        )
    rows = report.get("itemResults")
    if not isinstance(rows, list) or not rows:
        errors.append(f"{label}.itemResults: expected non-empty array")
        rows = []
    for index, row in enumerate(rows):
        _exact_keys(
            row,
            MAPPING_COVERAGE_ITEM_FIELDS,
            f"{label}.itemResults[{index}]",
            errors,
        )
    if rows != expected_rows:
        errors.append(
            f"{label}.itemResults: must be the exact canonical projection of every M "
            "mapping entry; missing, extra, or self-claimed rows are forbidden"
        )
    counts = {
        "BOUND": sum(item["disposition"] == "BOUND" for item in expected_rows),
        "AUTHORIZED_DEFERRED": sum(
            item["disposition"] == "AUTHORIZED_DEFERRED" for item in expected_rows
        ),
        "UNMAPPED": sum(item["disposition"] == "UNMAPPED" for item in expected_rows),
        "CONFLICT": sum(item["disposition"] == "CONFLICT" for item in expected_rows),
    }
    expected_summary = {
        "requiredCount": len(expected_rows),
        "boundCount": counts["BOUND"],
        "authorizedDeferredCount": counts["AUTHORIZED_DEFERRED"],
        "unmappedCount": counts["UNMAPPED"],
        "conflictCount": counts["CONFLICT"],
    }
    summary = report.get("summary")
    _exact_keys(summary, MAPPING_COVERAGE_SUMMARY_FIELDS, f"{label}.summary", errors)
    if summary != expected_summary:
        errors.append(f"{label}.summary: counters do not equal the exact M partition")
    if report.get("status") != "COMPLETE":
        errors.append(f"{label}.status: completion evidence must be COMPLETE")
    current_incomplete = any(
        item.get("releaseTrack") == "CURRENT_RELEASE_REQUIRED"
        and item.get("disposition") != "BOUND"
        for item in expected_rows
    )
    future_incomplete = any(
        item.get("releaseTrack") == "FUTURE_SEPARATELY_QUALIFIED"
        and item.get("disposition") not in {"BOUND", "AUTHORIZED_DEFERRED"}
        for item in expected_rows
    )
    if current_incomplete or future_incomplete or counts["UNMAPPED"] or counts["CONFLICT"]:
        errors.append(f"{label}: M does not satisfy the COMPLETE coverage predicate")


def _validate_conflict_report(
    report: Mapping[str, Any],
    mapping: Mapping[str, Any],
    hashes_by_role: Mapping[str, set[str]],
    label: str,
    errors: list[str],
) -> None:
    mappings = [
        item for item in mapping.get("mappings", []) if isinstance(item, Mapping)
    ]
    mapping_by_id = {item.get("contractItemId"): item for item in mappings}
    conflicts = report.get("conflicts")
    if not isinstance(conflicts, list):
        errors.append(f"{label}.conflicts: expected array")
        conflicts = []
    order: list[bytes] = []
    ids: list[Any] = []
    referenced: set[str] = set()
    open_conflict = False
    decision_hashes = hashes_by_role.get("CONFLICT_DECISION", set())
    for index, conflict in enumerate(conflicts):
        item_label = f"{label}.conflicts[{index}]"
        _exact_keys(conflict, CONFLICT_REPORT_ITEM_FIELDS, item_label, errors)
        if not isinstance(conflict, Mapping):
            continue
        conflict_id = conflict.get("conflictId")
        ids.append(conflict_id)
        try:
            order.append(canonical_json_bytes(conflict_id))
        except (CanonicalizationError, TypeError, ValueError) as exc:
            errors.append(f"{item_label}.conflictId: invalid order key: {exc}")
        contract_ids = _unique_strings(
            conflict.get("contractItemIds"), f"{item_label}.contractItemIds", errors
        )
        _require_canonical_set_order(
            conflict.get("contractItemIds"), f"{item_label}.contractItemIds", errors
        )
        unknown = set(contract_ids) - set(mapping_by_id)
        if unknown:
            errors.append(f"{item_label}.contractItemIds: unknown M items {sorted(unknown)}")
        referenced.update(contract_ids)
        if conflict.get("severity") not in {"BLOCKING", "NON_BLOCKING"}:
            errors.append(f"{item_label}.severity: unknown severity")
        state = conflict.get("state")
        if state == "OPEN":
            open_conflict = True
            if conflict.get("resolutionOrNull") is not None or conflict.get(
                "decisionDigestOrNull"
            ) is not None:
                errors.append(f"{item_label}: OPEN conflict cannot claim a resolution")
        elif state in {"RESOLVED", "AUTHORIZED_DEFERRED"}:
            if not isinstance(conflict.get("resolutionOrNull"), str) or not conflict.get(
                "resolutionOrNull"
            ):
                errors.append(f"{item_label}.resolutionOrNull: required by resolved state")
            decision_digest = conflict.get("decisionDigestOrNull")
            _is_digest(
                decision_digest,
                f"{item_label}.decisionDigestOrNull",
                errors,
                nonzero=True,
            )
            if decision_digest not in decision_hashes:
                errors.append(
                    f"{item_label}.decisionDigestOrNull: no exact CONFLICT_DECISION leaf"
                )
            if state == "AUTHORIZED_DEFERRED" and any(
                mapping_by_id.get(contract_id, {}).get("releaseTrack")
                != "FUTURE_SEPARATELY_QUALIFIED"
                for contract_id in contract_ids
            ):
                errors.append(
                    f"{item_label}: a current-release conflict cannot be deferred"
                )
        else:
            errors.append(f"{item_label}.state: unknown conflict state")
        _parse_time(conflict.get("discoveredAt"), f"{item_label}.discoveredAt", errors)
    if order != sorted(order) or len(ids) != len(set(ids)):
        errors.append(f"{label}.conflicts: conflictId values must be unique and sorted")
    required_conflicts = {
        item.get("contractItemId")
        for item in mappings
        if item.get("mappingStatus") == "CONFLICT"
    }
    if not required_conflicts.issubset(referenced):
        errors.append(
            f"{label}.conflicts: missing M conflict items "
            f"{sorted(required_conflicts - referenced)}"
        )
    if report.get("status") != "CLEAR":
        errors.append(f"{label}.status: completion evidence must be CLEAR")
    if open_conflict:
        errors.append(f"{label}: CLEAR cannot contain an OPEN conflict")


def _expected_implementation_test_runs(
    mapping: Mapping[str, Any],
    evidence_git: _GitView | None,
    label: str,
    errors: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    grouped: dict[tuple[Any, ...], set[str]] = {}
    binding_by_key: dict[tuple[Any, ...], Mapping[str, Any]] = {}
    for item in mapping.get("mappings", []):
        if not isinstance(item, Mapping):
            continue
        contract_id = item.get("contractItemId")
        for binding in item.get("targetTestBindings", []):
            if not isinstance(binding, Mapping):
                continue
            key = (
                binding.get("scenarioPath"),
                binding.get("scenarioId"),
                binding.get("scenarioSha256"),
                binding.get("executionEvidenceIndexRecordSha256"),
            )
            grouped.setdefault(key, set()).add(contract_id)
            binding_by_key.setdefault(key, binding)
    expected_runs: list[dict[str, Any]] = []
    plan: list[dict[str, Any]] = []
    used_run_ids: set[Any] = set()
    used_evidence_records: set[Any] = set()
    for key in sorted(grouped, key=lambda item: canonical_json_bytes(list(item))):
        binding = binding_by_key[key]
        contract_ids = sorted(grouped[key], key=canonical_json_bytes)
        path, scenario_id, scenario_digest, evidence_record = key
        blob = (
            evidence_git.blob(path, f"{label}.scenario[{scenario_id}].path", errors)
            if evidence_git is not None
            else None
        )
        if evidence_git is None:
            errors.append(f"{label}: pinned evidence E is unavailable")
        _check_blob_hash(blob, scenario_digest, f"{label}.scenario[{scenario_id}]", errors)
        scenario = (
            _load_json_bytes(blob, f"{label}.scenario[{scenario_id}]", errors)
            if blob is not None
            else None
        )
        result = scenario.get("executionResult") if isinstance(scenario, Mapping) else None
        if not isinstance(result, Mapping):
            errors.append(f"{label}.scenario[{scenario_id}]: signed executionResult missing")
            result = {}
        if not isinstance(scenario, Mapping) or scenario.get("definitionStatus") != "EXECUTED_PASS":
            errors.append(f"{label}.scenario[{scenario_id}]: expected EXECUTED_PASS")
        run_id = result.get("runId")
        if run_id in used_run_ids:
            errors.append(f"{label}: scenario run {run_id!r} is reused by another binding")
        used_run_ids.add(run_id)
        if evidence_record in used_evidence_records:
            errors.append(
                f"{label}: execution evidence record {evidence_record!r} is reused"
            )
        used_evidence_records.add(evidence_record)
        if result.get("evidenceIndexRecordSha256") != evidence_record:
            errors.append(
                f"{label}.scenario[{scenario_id}]: evidence-index record differs from M binding"
            )
        expected_runs.append(
            {
                "scenarioId": scenario_id,
                "scenarioSha256": scenario_digest,
                "scenarioRunId": run_id,
                "contractItemIds": contract_ids,
                "result": "EXECUTED_PASS",
                "startedAt": result.get("startedAt"),
                "completedAt": result.get("finishedAt"),
                "executionEvidenceIndexRecordSha256OrNull": evidence_record,
            }
        )
        plan.append(
            {
                "scenarioId": scenario_id,
                "scenarioSha256": scenario_digest,
                "contractItemIds": contract_ids,
            }
        )
    return expected_runs, plan


def _validate_implementation_test_report(
    report: Mapping[str, Any],
    mapping: Mapping[str, Any],
    contract: Mapping[str, Any],
    root: Path,
    code_git: _GitView | None,
    evidence_git: _GitView | None,
    trust: _TrustContext | None,
    hashes_by_role: Mapping[str, set[str]],
    label: str,
    errors: list[str],
) -> None:
    expected_runs, plan = _expected_implementation_test_runs(
        mapping, evidence_git, label, errors
    )
    plan_digest = _canonical_digest(plan, f"{label}.derivedTestPlan", errors)
    if report.get("testPlanDigest") != plan_digest:
        errors.append(
            f"{label}.testPlanDigest: must equal the exact C+M target-binding plan"
        )
    results = report.get("testResults")
    if not isinstance(results, list) or not results:
        errors.append(f"{label}.testResults: expected non-empty array")
        results = []
    identities: list[bytes] = []
    test_binding_ids: list[Any] = []
    observed_runs: list[dict[str, Any]] = []
    for index, result in enumerate(results):
        item_label = f"{label}.testResults[{index}]"
        _exact_keys(result, IMPLEMENTATION_TEST_RESULT_FIELDS, item_label, errors)
        if not isinstance(result, Mapping):
            continue
        test_binding_id = result.get("testBindingId")
        test_binding_ids.append(test_binding_id)
        try:
            identities.append(
                canonical_json_bytes([test_binding_id, result.get("scenarioRunId")])
            )
        except (CanonicalizationError, TypeError, ValueError) as exc:
            errors.append(f"{item_label}: invalid canonical order key: {exc}")
        contract_ids = _unique_strings(
            result.get("contractItemIds"), f"{item_label}.contractItemIds", errors
        )
        _require_canonical_set_order(
            result.get("contractItemIds"), f"{item_label}.contractItemIds", errors
        )
        observed_runs.append(
            {
                "scenarioId": result.get("scenarioId"),
                "scenarioSha256": result.get("scenarioSha256"),
                "scenarioRunId": result.get("scenarioRunId"),
                "contractItemIds": contract_ids,
                "result": result.get("result"),
                "startedAt": result.get("startedAt"),
                "completedAt": result.get("completedAt"),
                "executionEvidenceIndexRecordSha256OrNull": result.get(
                    "executionEvidenceIndexRecordSha256OrNull"
                ),
            }
        )
        _parse_time(result.get("startedAt"), f"{item_label}.startedAt", errors)
        _parse_time(result.get("completedAt"), f"{item_label}.completedAt", errors)
    if identities != sorted(identities) or len(test_binding_ids) != len(
        set(test_binding_ids)
    ):
        errors.append(
            f"{label}.testResults: testBindingId values must be unique and rows sorted "
            "by [testBindingId,scenarioRunId]"
        )
    expected_sorted = sorted(expected_runs, key=canonical_json_bytes)
    observed_sorted = sorted(observed_runs, key=canonical_json_bytes)
    if observed_sorted != expected_sorted:
        errors.append(
            f"{label}.testResults: must exactly equal all independently resolved "
            "targetTestBindings; missing, extra, failed, or reused rows are forbidden"
        )
    if report.get("status") != "PASS":
        errors.append(f"{label}.status: completion evidence must be PASS")
    if report.get("buildResult") != "PASSED":
        errors.append(f"{label}.buildResult: completion evidence requires PASSED")
    expected_summary = {
        "requiredCount": len(expected_runs),
        "passedCount": len(expected_runs),
        "failedCount": 0,
        "notExecutedCount": 0,
        "invalidEvidenceCount": 0,
    }
    summary = report.get("summary")
    _exact_keys(summary, IMPLEMENTATION_TEST_SUMMARY_FIELDS, f"{label}.summary", errors)
    if summary != expected_summary:
        errors.append(f"{label}.summary: counters do not equal the exact test partition")
    expected_scenarios = {item["scenarioSha256"] for item in expected_runs}
    missing_scenario_leaves = expected_scenarios - hashes_by_role.get(
        "ACCEPTANCE_SCENARIO", set()
    )
    if missing_scenario_leaves:
        errors.append(
            f"{label}.evidenceContentHashes: missing exact ACCEPTANCE_SCENARIO leaves "
            f"{sorted(missing_scenario_leaves)}"
        )

    policy_blob = _worktree_bytes(
        root,
        "contracts/compatibility-profile-policy.json",
        f"{label}.platformPolicy",
        errors,
    )
    policy = (
        _load_json_bytes(policy_blob, f"{label}.platformPolicy", errors)
        if policy_blob is not None
        else None
    )
    governed_platforms = {
        item.get("id")
        for item in (
            policy.get("platforms", []) if isinstance(policy, Mapping) else []
        )
        if isinstance(item, Mapping) and isinstance(item.get("id"), str)
    }
    declared_platforms = _unique_strings(
        report.get("platformProfileIds"), f"{label}.platformProfileIds", errors
    )
    _require_canonical_set_order(
        report.get("platformProfileIds"), f"{label}.platformProfileIds", errors
    )
    if set(declared_platforms) != governed_platforms:
        errors.append(
            f"{label}.platformProfileIds: must exactly equal governed target platforms"
        )
    case_registry = _load_case_contract_registry(contract, root, errors)
    registry_records = (
        case_registry.get("records", [])
        if isinstance(case_registry, Mapping)
        else []
    )
    product_records = [
        item
        for item in registry_records
        if isinstance(item, Mapping)
        and isinstance(item.get("classification"), Mapping)
        and item["classification"].get("scope") == "PRODUCT"
    ]
    blocked_product_cases = sorted(
        item.get("caseId")
        for item in product_records
        if item["classification"].get("status") != "EXECUTABLE"
    )
    executable_case_ids = {
        item.get("caseId")
        for item in product_records
        if item["classification"].get("status") == "EXECUTABLE"
    }
    if report.get("status") == "PASS" and blocked_product_cases:
        errors.append(
            f"{label}: PASS is impossible while PRODUCT Cases remain non-EXECUTABLE "
            f"{blocked_product_cases}"
        )

    descriptors = report.get("caseCompletionRecords")
    if not isinstance(descriptors, list):
        errors.append(f"{label}.caseCompletionRecords: expected array")
        descriptors = []
    descriptor_order: list[bytes] = []
    completion_bundles: list[Mapping[str, Any]] = []
    descriptor_pairs: list[tuple[Any, Any]] = []
    descriptor_paths: set[Any] = set()
    descriptor_hashes: set[Any] = set()
    descriptor_digests: set[Any] = set()
    for number, descriptor in enumerate(descriptors):
        descriptor_label = f"{label}.caseCompletionRecords[{number}]"
        if not isinstance(descriptor, Mapping):
            errors.append(f"{descriptor_label}: expected object")
            continue
        try:
            descriptor_order.append(
                canonical_json_bytes(
                    [
                        descriptor.get("platformProfileId"),
                        descriptor.get("caseId"),
                        descriptor.get("targetCommit"),
                        descriptor.get("mappingCoreId"),
                        descriptor.get("completionDigest"),
                        descriptor.get("path"),
                        descriptor.get("sha256"),
                    ]
                )
            )
        except (CanonicalizationError, TypeError, ValueError) as exc:
            errors.append(f"{descriptor_label}: invalid canonical order key: {exc}")
        pair = (descriptor.get("platformProfileId"), descriptor.get("caseId"))
        descriptor_pairs.append(pair)
        for field, seen in (
            ("path", descriptor_paths),
            ("sha256", descriptor_hashes),
            ("completionDigest", descriptor_digests),
        ):
            value = descriptor.get(field)
            if value in seen:
                errors.append(f"{descriptor_label}.{field}: duplicate/reused value")
            seen.add(value)
        bundle = _validate_case_completion_artifact(
            descriptor,
            descriptor_fields=IMPLEMENTATION_CASE_COMPLETION_DESCRIPTOR_FIELDS,
            expected_platform_id=descriptor.get("platformProfileId"),
            code_git=code_git,
            evidence_git=evidence_git,
            root=root,
            contract=contract,
            mapping=mapping,
            trust=trust,
            case_registry=case_registry,
            label=descriptor_label,
            errors=errors,
        )
        if isinstance(bundle, Mapping):
            completion_bundles.append(bundle)
    if descriptor_order != sorted(descriptor_order) or len(descriptor_pairs) != len(
        set(descriptor_pairs)
    ):
        errors.append(
            f"{label}.caseCompletionRecords: duplicate identity or non-canonical order"
        )
    expected_pairs = {
        (platform_id, case_id)
        for platform_id in governed_platforms
        for case_id in executable_case_ids
    }
    if set(descriptor_pairs) != expected_pairs:
        errors.append(
            f"{label}.caseCompletionRecords: expected platform/Case closure "
            f"{sorted(expected_pairs)}, actual {sorted(set(descriptor_pairs))}"
        )
    _validate_case_completion_set(completion_bundles, label, errors)
    _validate_e4_completion_subject_groups(
        completion_bundles,
        case_registry=case_registry,
        trust=trust,
        root=root,
        code_git=code_git,
        evidence_git=evidence_git,
        mapping=mapping,
        label=f"{label}.caseCompletionRecords",
        errors=errors,
    )

    completion_runs = sorted(
        (
            row.get("scenarioId"),
            row.get("scenarioSha256"),
            row.get("scenarioRunId"),
            row.get("evidenceIndexRecordSha256"),
        )
        for bundle in completion_bundles
        for row in bundle.get("scenarioRows", [])
        if isinstance(row, Mapping)
    )
    result_runs = sorted(
        (
            item.get("scenarioId"),
            item.get("scenarioSha256"),
            item.get("scenarioRunId"),
            item.get("executionEvidenceIndexRecordSha256OrNull"),
        )
        for item in results
        if isinstance(item, Mapping) and item.get("result") == "EXECUTED_PASS"
    )
    if completion_runs != result_runs:
        errors.append(
            f"{label}.caseCompletionRecords: transitive scenarios must form an exact "
            "bijection with EXECUTED_PASS testResults"
        )
    expected_completion_leaves = sorted(
        (
            descriptor.get("path"),
            descriptor.get("sha256"),
        )
        for descriptor in descriptors
        if isinstance(descriptor, Mapping)
    )
    observed_completion_leaves = sorted(
        (item.get("path"), item.get("sha256"))
        for item in report.get("evidenceContentHashes", [])
        if isinstance(item, Mapping)
        and item.get("artifactRole") == "CASE_COMPLETION_RECORD"
        and item.get("mediaType") == "application/json"
    )
    if observed_completion_leaves != expected_completion_leaves:
        errors.append(
            f"{label}.evidenceContentHashes: CASE_COMPLETION_RECORD leaves must "
            "exactly equal completion descriptors"
        )


def _validate_integration_report(
    blob: bytes | None,
    descriptor: Mapping[str, Any],
    expected_report_type: str,
    mapping: Mapping[str, Any],
    contract: Mapping[str, Any],
    root: Path,
    code_git: _GitView | None,
    evidence_git: _GitView | None,
    trust: _TrustContext | None,
    label: str,
    errors: list[str],
) -> None:
    if blob is None:
        return
    report = _load_json_bytes(blob, label, errors)
    required_fields = INTEGRATION_REPORT_FIELDS | INTEGRATION_REPORT_TYPE_FIELDS[
        expected_report_type
    ]
    _exact_keys(report, required_fields, label, errors)
    if not isinstance(report, Mapping):
        return
    if report.get("reportType") != expected_report_type:
        errors.append(f"{label}.reportType: expected {expected_report_type}")
    if report.get("schemaVersion") != 1:
        errors.append(f"{label}.schemaVersion: expected 1")
    if report.get("canonicalProfileId") != "CANONICAL-JSON-V1":
        errors.append(f"{label}.canonicalProfileId: unsupported profile")
    if report.get("publicationState") != "FINAL":
        errors.append(f"{label}.publicationState: completion evidence must be FINAL")
    if not isinstance(report.get("reportId"), str) or not report.get("reportId"):
        errors.append(f"{label}.reportId: expected non-empty identifier")
    sequence = report.get("reportSequence")
    if (
        not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or sequence < 1
        or sequence > SAFE_INTEGER
    ):
        errors.append(f"{label}.reportSequence: expected positive safe integer")
    _parse_time(report.get("generatedAt"), f"{label}.generatedAt", errors)
    limitations = _unique_strings(
        report.get("limitations"), f"{label}.limitations", errors, nonempty=False
    )
    _require_canonical_set_order(report.get("limitations"), f"{label}.limitations", errors)
    if limitations:
        errors.append(f"{label}.limitations: a limited report cannot close a status axis")

    source = mapping.get("sourceContract")
    expected_contract = {
        "contractId": contract.get("contractId"),
        "revision": contract.get("revision"),
        "sha256": source.get("sha256") if isinstance(source, Mapping) else None,
    }
    _exact_keys(
        report.get("portableContract"),
        INTEGRATION_PORTABLE_CONTRACT_FIELDS,
        f"{label}.portableContract",
        errors,
    )
    if report.get("portableContract") != expected_contract:
        errors.append(f"{label}.portableContract: does not bind the exact portable source")

    repository = mapping.get("targetRepository")
    locator_subject = {
        "repositoryId": repository.get("repositoryId")
        if isinstance(repository, Mapping)
        else None,
        "repositoryLocation": repository.get("repositoryLocation")
        if isinstance(repository, Mapping)
        else None,
    }
    locator_digest = _canonical_digest(
        locator_subject, f"{label}.targetCodeRevision.repositoryLocator", errors
    )
    expected_target = {
        "repositoryId": repository.get("repositoryId")
        if isinstance(repository, Mapping)
        else None,
        "repositoryLocatorDigest": locator_digest,
        "objectFormat": (
            {"SHA1": "GIT_SHA1", "SHA256": "GIT_SHA256"}.get(
                repository.get("objectFormat")
            )
            if isinstance(repository, Mapping)
            else None
        ),
        "revision": code_git.commit if code_git is not None else None,
    }
    _exact_keys(
        report.get("targetCodeRevision"),
        INTEGRATION_TARGET_CODE_FIELDS,
        f"{label}.targetCodeRevision",
        errors,
    )
    if report.get("targetCodeRevision") != expected_target:
        errors.append(f"{label}.targetCodeRevision: does not bind immutable C exactly")
    expected_core = {
        "mappingCoreId": mapping.get("mappingCoreId"),
        "mappingCoreDigest": mapping.get("scenarioBindingDigest"),
    }
    _exact_keys(
        report.get("mappingCore"),
        INTEGRATION_MAPPING_CORE_FIELDS,
        f"{label}.mappingCore",
        errors,
    )
    if report.get("mappingCore") != expected_core:
        errors.append(f"{label}.mappingCore: does not bind detached M exactly")

    hashes_by_role = _validate_report_evidence_content(
        report.get("evidenceContentHashes"),
        evidence_git,
        descriptor,
        report,
        label,
        errors,
    )
    expected_role = INTEGRATION_REPORT_ROLES[expected_report_type]
    if report.get("signerRole") != expected_role:
        errors.append(f"{label}.signerRole: expected {expected_role}")
    _verify_signed_envelope(
        report,
        digest_field="reportDigest",
        signature_field="signature",
        signer_field="signerKeyId",
        signed_time_field="generatedAt",
        domain=(
            "QMAN-DIRECTPATH/INTEGRATION-REPORT/V1\x00" + expected_report_type
        ),
        required_role=expected_role,
        trust=trust,
        label=label,
        errors=errors,
    )
    if expected_report_type == "MAPPING_COVERAGE_REPORT":
        _validate_mapping_coverage_report(report, mapping, label, errors)
    elif expected_report_type == "CONFLICT_REGISTER":
        _validate_conflict_report(report, mapping, hashes_by_role, label, errors)
    elif expected_report_type == "IMPLEMENTATION_TEST_REPORT":
        _validate_implementation_test_report(
            report,
            mapping,
            contract,
            root,
            code_git,
            evidence_git,
            trust,
            hashes_by_role,
            label,
            errors,
        )


def _map_approval_projection(mapping: Mapping[str, Any]) -> dict[str, Any]:
    projection = copy.deepcopy(dict(mapping))
    projection["mapDigest"] = None
    projection["approvals"] = []
    return projection


def _repository_tree_v1(root: Path, directory: Path, label: str, errors: list[str]) -> str | None:
    try:
        root_resolved = root.resolve(strict=True)
        directory_resolved = directory.resolve(strict=True)
        directory_resolved.relative_to(root_resolved)
    except (OSError, ValueError) as exc:
        errors.append(f"{label}: invalid tree root: {exc}")
        return None
    if not directory_resolved.is_dir():
        errors.append(f"{label}: tree target is not a directory")
        return None
    records: list[dict[str, str]] = []
    try:
        paths: list[Path] = []
        for current, directories, files in os.walk(directory_resolved, followlinks=False):
            current_path = Path(current)
            for name in list(directories):
                child = current_path / name
                if name == ".git":
                    errors.append(f"{label}: .git entry is forbidden in normative tree: {child}")
                    directories.remove(name)
                elif child.is_symlink():
                    errors.append(f"{label}: symlink is forbidden in normative tree: {child}")
                    directories.remove(name)
            for name in files:
                path = current_path / name
                if name == ".git" or path.is_symlink():
                    errors.append(f"{label}: .git/symlink is forbidden in normative tree: {path}")
                    continue
                paths.append(path)
        path_records: list[tuple[bytes, str, Path]] = []
        folded: dict[str, str] = {}
        for path in paths:
            relative = path.relative_to(directory_resolved).as_posix()
            _validate_unicode(relative, f"{label} path")
            collision_key = unicodedata.normalize("NFC", relative).casefold()
            if collision_key in folded and folded[collision_key] != relative:
                errors.append(
                    f"{label}: NFC/case-fold path collision {folded[collision_key]!r} vs {relative!r}"
                )
            folded[collision_key] = relative
            path_records.append((canonical_json_bytes(relative), relative, path))
        for _, relative, path in sorted(path_records, key=lambda item: item[0]):
            raw = path.read_bytes()
            if b"\r" in raw:
                errors.append(f"{label}: normative repository file is not exact LF bytes: {relative}")
            records.append({"path": relative, "sha256": sha256(raw)})
    except (OSError, CanonicalizationError) as exc:
        errors.append(f"{label}: cannot enumerate tree: {exc}")
        return None
    return _canonical_digest(records, f"{label} REPOSITORY_TREE_V1", errors)


def _validate_normative_source_closure(
    contract: Mapping[str, Any], root: Path, errors: list[str]
) -> None:
    closure = contract.get("normativeSourceClosure")
    if not isinstance(closure, list) or not closure:
        errors.append("portable contract.normativeSourceClosure: non-empty closed list is required")
        return
    seen: set[str] = set()
    for index, item in enumerate(closure):
        label = f"portable contract.normativeSourceClosure[{index}]"
        _exact_keys(item, {"path", "hashScope", "sha256"}, label, errors)
        if not isinstance(item, Mapping):
            continue
        path = _safe_relative_path(item.get("path"), f"{label}.path", errors)
        if path is None:
            continue
        if path in seen:
            errors.append(f"{label}.path: duplicate closure path {path}")
        seen.add(path)
        declared = item.get("sha256")
        if not _is_digest(declared, f"{label}.sha256", errors):
            continue
        scope = item.get("hashScope")
        if scope == "GIT_BLOB_BYTES":
            blob = _worktree_bytes(root, path, f"{label}.path", errors)
            actual = sha256(blob) if blob is not None else None
        elif scope == "REPOSITORY_TREE_V1":
            actual = _repository_tree_v1(
                root, root.joinpath(*PurePosixPath(path).parts), label, errors
            )
        else:
            errors.append(f"{label}.hashScope: unsupported scope {scope!r}")
            actual = None
        if actual is not None and declared != actual:
            errors.append(f"{label}.sha256: declared {declared}, actual {actual}")
    normative_sources = contract.get("normativeSources")
    if not isinstance(normative_sources, list) or not all(
        isinstance(item, str) and item for item in normative_sources
    ):
        errors.append("portable contract.normativeSources: expected ordered non-empty paths")
    else:
        closure_paths = [
            item.get("path") if isinstance(item, Mapping) else None for item in closure
        ]
        if normative_sources != closure_paths:
            missing = sorted(set(normative_sources) - set(closure_paths))
            extra = sorted(set(closure_paths) - set(normative_sources))
            errors.append(
                "portable contract.normativeSourceClosure: paths/order must exactly equal "
                f"normativeSources (missing={missing}, extra={extra})"
            )


def _contract_indexes(contract: Mapping[str, Any]) -> dict[str, Any]:
    machines = {item["id"]: item for item in contract.get("stateMachines", [])}
    operations = {
        item["id"]: item for item in contract.get("backendNeutralOperations", [])
    }
    transitions = {
        transition["id"]: {"machine": machine, "transition": transition}
        for machine in contract.get("stateMachines", [])
        for transition in machine.get("transitions", [])
    }
    return {
        "ports": {item["id"] for item in contract.get("requiredPorts", [])},
        "entities": {item["id"] for item in contract.get("dataEntities", [])},
        "entity_records": {item["id"]: item for item in contract.get("dataEntities", [])},
        "operations": set(operations),
        "operation_records": operations,
        "reasons": {
            item["code"]: item for item in contract.get("errorContract", {}).get("reasonCodes", [])
        },
        "machines": machines,
        "transitions": transitions,
        "states": {machine_id: set(machine.get("states", [])) for machine_id, machine in machines.items()},
        "cases": {
            case_id
            for obligation in contract.get("acceptanceObligations", [])
            for case_id in obligation.get("caseIds", [])
        },
        "tests": {
            item["id"]: item for item in contract.get("acceptanceObligations", [])
        },
        "parity": {
            item["id"]: item for item in contract.get("vmwareParityObligations", [])
        },
        "tech_stories": {
            story_id
            for obligation in contract.get("acceptanceObligations", [])
            for story_id in obligation.get("techStoryIds", [])
        },
    }


def _load_risk_ids(root: Path, errors: list[str]) -> set[str]:
    path = root / "contracts" / "risk-status.json"
    try:
        data = path.read_bytes()
    except OSError as exc:
        errors.append(f"risk registry: cannot read {path}: {exc}")
        return set()
    document = _load_json_bytes(data, "risk registry", errors)
    if not isinstance(document, Mapping) or not isinstance(document.get("records"), list):
        errors.append("risk registry: records array is missing")
        return set()
    result = {
        item.get("id")
        for item in document["records"]
        if isinstance(item, Mapping) and isinstance(item.get("id"), str)
    }
    expected = document.get("expectedRiskCount")
    if isinstance(expected, int) and expected != len(result):
        errors.append(f"risk registry: expected {expected} unique records, found {len(result)}")
    return result


def _validate_symbol_index(
    blob: bytes | None,
    binding: Mapping[str, Any],
    git: _GitView | None,
    trust: _TrustContext | None,
    label: str,
    errors: list[str],
) -> None:
    if blob is None:
        return
    index = _load_json_bytes(blob, f"{label}.resolverEvidence", errors)
    if not isinstance(index, Mapping):
        return
    _exact_keys(index, SYMBOL_INDEX_FIELDS, f"{label}.resolverEvidence", errors)
    if index.get("schemaVersion") != 1:
        errors.append(f"{label}.resolverEvidence.schemaVersion: expected 1")
    commit = _normal_commit(
        index.get("targetRepositoryCommit"),
        f"{label}.resolverEvidence.targetRepositoryCommit",
        errors,
    )
    if git is not None and commit != git.commit:
        errors.append(f"{label}.resolverEvidence: symbol index is for another target commit")
    generator = index.get("generator")
    _exact_keys(generator, SYMBOL_GENERATOR_FIELDS, f"{label}.resolverEvidence.generator", errors)
    if isinstance(generator, Mapping):
        for field in ("binarySha256", "configurationSha256"):
            _is_digest(generator.get(field), f"{label}.resolverEvidence.generator.{field}", errors, nonzero=True)
        for field in ("tool", "version"):
            if not isinstance(generator.get(field), str) or not generator.get(field):
                errors.append(f"{label}.resolverEvidence.generator.{field}: expected non-empty string")
    entries = index.get("entries")
    if not isinstance(entries, list) or not entries:
        errors.append(f"{label}.resolverEvidence.entries: expected non-empty array")
        entries = []
    entry_keys: list[bytes] = []
    exact_matches: list[Mapping[str, Any]] = []
    expected = {
        "service": binding.get("service"),
        "path": binding.get("path"),
        "symbol": binding.get("symbol"),
        "symbolKind": binding.get("symbolKind"),
        "symbolResolver": binding.get("symbolResolver"),
        "symbolLocator": binding.get("symbolLocator"),
        "sourceBlobSha256": binding.get("interfaceHash"),
        "symbolSemanticHash": binding.get("symbolSemanticHash"),
    }
    for index_number, entry in enumerate(entries):
        entry_label = f"{label}.resolverEvidence.entries[{index_number}]"
        _exact_keys(entry, SYMBOL_ENTRY_FIELDS, entry_label, errors)
        if not isinstance(entry, Mapping):
            continue
        for field in ("sourceBlobSha256", "symbolSemanticHash"):
            _is_digest(entry.get(field), f"{entry_label}.{field}", errors, nonzero=True)
        key = [entry.get(field) for field in ("service", "path", "symbol", "symbolKind")]
        try:
            entry_keys.append(canonical_json_bytes(key))
        except (CanonicalizationError, TypeError, ValueError) as exc:
            errors.append(f"{entry_label}: invalid canonical order key: {exc}")
        if dict(entry) == expected:
            exact_matches.append(entry)
    if entry_keys != sorted(entry_keys) or len(entry_keys) != len(set(entry_keys)):
        errors.append(
            f"{label}.resolverEvidence.entries: must be unique and sorted by canonical [service,path,symbol,symbolKind]"
        )
    if len(exact_matches) != 1:
        errors.append(
            f"{label}: signed symbol index contains {len(exact_matches)} exact entries; expected exactly one"
        )
    _verify_signed_envelope(
        index,
        digest_field="indexDigest",
        signature_field="signature",
        signer_field="signerKeyId",
        signed_time_field="issuedAt",
        domain="QMAN-DIRECTPATH/TARGET-SYMBOL-INDEX/V1",
        required_role="TARGET_ARCHITECT",
        trust=trust,
        label=f"{label}.resolverEvidence",
        errors=errors,
    )


def _validate_target_binding(
    binding: Any,
    code_git: _GitView | None,
    evidence_git: _GitView | None,
    trust: _TrustContext | None,
    label: str,
    errors: list[str],
) -> None:
    _exact_keys(binding, TARGET_BINDING_FIELDS, label, errors)
    if not isinstance(binding, Mapping):
        return
    if binding.get("hashScope") != "GIT_BLOB_BYTES":
        errors.append(f"{label}.hashScope: only GIT_BLOB_BYTES is authoritative")
    for field in ("service", "symbol", "symbolKind", "symbolResolver", "symbolLocator"):
        if not isinstance(binding.get(field), str) or not binding.get(field):
            errors.append(f"{label}.{field}: expected non-empty string")
    blob = (
        code_git.blob(binding.get("path"), f"{label}.path", errors)
        if code_git
        else None
    )
    _check_blob_hash(blob, binding.get("interfaceHash"), label, errors)
    _is_digest(binding.get("symbolSemanticHash"), f"{label}.symbolSemanticHash", errors, nonzero=True)
    evidence_blob = (
        evidence_git.blob(
            binding.get("resolverEvidencePath"),
            f"{label}.resolverEvidencePath",
            errors,
        )
        if evidence_git
        else None
    )
    _check_blob_hash(
        evidence_blob,
        binding.get("resolverEvidenceSha256"),
        f"{label}.resolverEvidence",
        errors,
    )
    _validate_symbol_index(evidence_blob, binding, code_git, trust, label, errors)


def _validate_defer_decision(
    decision: Any, root: Path, label: str, errors: list[str]
) -> None:
    _exact_keys(decision, DEFER_FIELDS, label, errors)
    if not isinstance(decision, Mapping):
        return
    expected_literals = {
        "authorityPath": "contracts/product-decisions.json",
        "authorityDecisionId": "ADR-002",
        "decision": "DEFER_CURRENT_RELEASE",
        "releaseTrack": "FUTURE_SEPARATELY_QUALIFIED",
        "authorizationModel": "PORTABLE_NORMATIVE_SOURCE_CLOSURE",
    }
    for field, expected in expected_literals.items():
        if decision.get(field) != expected:
            errors.append(f"{label}.{field}: expected {expected}")
    blob = _worktree_bytes(
        root, decision.get("authorityPath"), f"{label}.authorityPath", errors
    )
    if blob is not None:
        actual = sha256(blob)
        for field in ("authoritySha256", "approvalEvidenceHash"):
            _is_digest(decision.get(field), f"{label}.{field}", errors)
            if decision.get(field) != actual:
                errors.append(f"{label}.{field}: declared {decision.get(field)}, actual {actual}")
        authority = _load_json_bytes(blob, f"{label}.authority", errors)
        records = authority.get("records") if isinstance(authority, Mapping) else None
        selected = [
            item
            for item in (records if isinstance(records, list) else [])
            if isinstance(item, Mapping)
            and item.get("id") == decision.get("authorityDecisionId")
            and item.get("status") == "ACCEPTED"
        ]
        if len(selected) != 1:
            errors.append(
                f"{label}.authorityDecisionId: expected exactly one ACCEPTED "
                f"record, found {len(selected)}"
            )
        else:
            decision_text = selected[0].get("decision")
            if not isinstance(decision_text, str) or not all(
                token in decision_text.casefold() for token in ("iommufd", "cdev")
            ):
                errors.append(
                    f"{label}.authorityDecisionId: ADR-002 must explicitly place "
                    "IOMMUFD/cdev in the separately qualified future track"
                )


def _validate_transition_execution_binding(
    binding: Any,
    transition_id: Any,
    contract: Mapping[str, Any],
    label: str,
    errors: list[str],
) -> None:
    _exact_keys(binding, TRANSITION_BINDING_FIELDS, label, errors)
    if not isinstance(binding, Mapping):
        return
    transition: Mapping[str, Any] | None = None
    parent_machine: Mapping[str, Any] | None = None
    all_transitions: dict[str, Mapping[str, Any]] = {}
    for machine in contract.get("stateMachines", []):
        if not isinstance(machine, Mapping):
            continue
        for candidate in machine.get("transitions", []):
            if isinstance(candidate, Mapping) and isinstance(candidate.get("id"), str):
                all_transitions[candidate["id"]] = candidate
                if candidate["id"] == transition_id:
                    transition = candidate
                    parent_machine = machine
    if transition is None or parent_machine is None:
        errors.append(f"{label}: mapping references unknown transition {transition_id!r}")
        return
    exact_values = {
        "fsmId": parent_machine.get("id"),
        "fromState": transition.get("from"),
        "toState": transition.get("to"),
        "successAuthoritativeState": transition.get("to"),
    }
    for field, expected in exact_values.items():
        if binding.get(field) != expected:
            errors.append(f"{label}.{field}: expected {expected!r}")
    expected_concrete_from = transition.get("fromStateExpansion")
    if expected_concrete_from is None:
        expected_concrete_from = [transition.get("from")]
    if binding.get("concreteFromStates") != expected_concrete_from:
        errors.append(
            f"{label}.concreteFromStates: expected exact concrete expansion {expected_concrete_from}"
        )
    operations_by_id = {
        item.get("id"): item
        for item in contract.get("backendNeutralOperations", [])
        if isinstance(item, Mapping)
    }
    ordered = binding.get("orderedOperations")
    if not isinstance(ordered, list) or not ordered:
        errors.append(f"{label}.orderedOperations: expected non-empty array")
        ordered = []
    expected_operations = transition.get("operationIds", [])
    actual_operations: list[Any] = []
    for index, item in enumerate(ordered):
        item_label = f"{label}.orderedOperations[{index}]"
        _exact_keys(item, ORDERED_OPERATION_FIELDS, item_label, errors)
        if not isinstance(item, Mapping):
            continue
        if item.get("sequence") != index + 1:
            errors.append(f"{item_label}.sequence: expected {index + 1}")
        operation_id = item.get("operationId")
        actual_operations.append(operation_id)
        operation = operations_by_id.get(operation_id)
        if operation is None:
            errors.append(f"{item_label}.operationId: unknown operation {operation_id!r}")
        elif item.get("logicalActorPortId") != operation.get("ownerPortId"):
            errors.append(
                f"{item_label}.logicalActorPortId: expected {operation.get('ownerPortId')!r}"
            )
        if item.get("executionPhase") not in {
            "DURABLE_INTENT",
            "HOST_SIDE_EFFECT",
            "EXTERNAL_PROCESS",
            "OBSERVATION",
            "ATOMIC_COMMIT",
        }:
            errors.append(f"{item_label}.executionPhase: unknown phase")
        declared_lease = item.get("requiredLeaseTypeOrNull")
        if declared_lease is not None and declared_lease not in OPERATION_LEASE_TYPES:
            errors.append(
                f"{item_label}.requiredLeaseTypeOrNull: unknown lease type {declared_lease!r}"
            )
        expected_lease = _expected_operation_lease_type(
            operation_id,
            transition,
            parent_machine,
            item.get("executionPhase"),
        )
        if declared_lease != expected_lease:
            errors.append(
                f"{item_label}.requiredLeaseTypeOrNull: expected contextual "
                f"{expected_lease!r}, found {declared_lease!r}"
            )
        expected_release_guard = _expected_operation_release_guard(operation_id, transition)
        if item.get("requiredReleaseGuard") is not expected_release_guard:
            errors.append(
                f"{item_label}.requiredReleaseGuard: expected "
                f"{expected_release_guard} for {operation_id!r}"
            )
        if item.get("requiredReleaseGuard") is True and declared_lease != "RELEASE":
            errors.append(
                f"{item_label}: a release guard is valid only with RELEASE authority"
            )
        if (
            item.get("executionPhase") in {"HOST_SIDE_EFFECT", "EXTERNAL_PROCESS"}
            and declared_lease is None
        ):
            errors.append(
                f"{item_label}: {item.get('executionPhase')} requires a non-null typed operation lease"
            )
    if actual_operations != expected_operations:
        errors.append(
            f"{label}.orderedOperations: exact operation order is {expected_operations}, found {actual_operations}"
        )
    side_effect_sequences = [
        item.get("sequence")
        for item in ordered
        if isinstance(item, Mapping)
        and item.get("executionPhase") in {"HOST_SIDE_EFFECT", "EXTERNAL_PROCESS"}
        and isinstance(item.get("sequence"), int)
    ]
    journal = binding.get("intentJournal")
    if journal is not None:
        _exact_keys(journal, INTENT_JOURNAL_FIELDS, f"{label}.intentJournal", errors)
        if isinstance(journal, Mapping):
            if journal.get("journalEntityId") != "ENTITY-HOST-ACTION-JOURNAL":
                errors.append(f"{label}.intentJournal.journalEntityId: expected host action journal")
            if journal.get("intentState") != "INTENT":
                errors.append(f"{label}.intentJournal.intentState: expected exact 'INTENT'")
            if journal.get("fsyncRequired") is not True:
                errors.append(f"{label}.intentJournal.fsyncRequired: must be true")
            intent_sequence = journal.get("intentBeforeOperationSequence")
            if not isinstance(intent_sequence, int) or isinstance(intent_sequence, bool) or intent_sequence < 1:
                errors.append(f"{label}.intentJournal.intentBeforeOperationSequence: invalid sequence")
            elif side_effect_sequences and intent_sequence > min(side_effect_sequences):
                errors.append(f"{label}.intentJournal: durable intent is not before first side effect")
    elif side_effect_sequences:
        errors.append(f"{label}.intentJournal: host/external side effects require an fsynced intent")
    for field in (
        "expectedVersionFields",
        "sameTransactionWriteEntityIds",
        "outboxEventTypes",
        "compensationTransitionIds",
        "crashTestScenarioIds",
    ):
        if not isinstance(binding.get(field), list):
            errors.append(f"{label}.{field}: expected array")
        else:
            _require_canonical_set_order(binding[field], f"{label}.{field}", errors)
    allowed_versions = {
        "controllerGeneration",
        "resourceVersion",
        "snapshotEpoch",
        "hostEpoch",
        "runGeneration",
        "leaseVersion",
        "quarantineGeneration",
        "relocationGeneration",
    }
    version_fields = set(binding.get("expectedVersionFields", [])) if isinstance(binding.get("expectedVersionFields"), list) else set()
    unknown_versions = sorted(version_fields - allowed_versions)
    if unknown_versions:
        errors.append(f"{label}.expectedVersionFields: unknown version fields {unknown_versions}")
    cas_version_fields = {
        "CAS-CONTROLLER-AUTHORITY": {"controllerGeneration", "resourceVersion"},
        "CAS-OPERATION-LEASE": {
            "hostEpoch",
            "runGeneration",
            "controllerGeneration",
            "resourceVersion",
            "leaseVersion",
        },
        "CAS-RELEASE-GUARD": {
            "hostEpoch",
            "runGeneration",
            "controllerGeneration",
            "resourceVersion",
            "leaseVersion",
        },
        "CAS-IDEMPOTENCY": set(),
        "CAS-SNAPSHOT-EPOCH": {"snapshotEpoch"},
        "CAS-RESOURCE-VERSION": {"resourceVersion"},
        "CAS-BUNDLE-EXCLUSIVITY": {"leaseVersion", "quarantineGeneration"},
        "CAS-RUN-GENERATION": {"runGeneration"},
        "CAS-HOST-EPOCH": {"hostEpoch"},
        "CAS-ASSIGNED-ID-LIFETIME": {"runGeneration"},
        "CAS-CLEAN-RELEASE": {
            "hostEpoch",
            "runGeneration",
            "leaseVersion",
            "controllerGeneration",
        },
        "CAS-RELOCATION-HANDOFF": {
            "relocationGeneration",
            "hostEpoch",
            "runGeneration",
        },
        "CAS-QUARANTINE-STICKY": {
            "quarantineGeneration",
            "leaseVersion",
            "controllerGeneration",
            "resourceVersion",
        },
    }
    expected_versions: set[str] = set()
    for cas_rule_id in transition.get("casRuleIds", []):
        if cas_rule_id not in cas_version_fields:
            errors.append(f"{label}: no executable version-field derivation for {cas_rule_id}")
        else:
            expected_versions.update(cas_version_fields[cas_rule_id])
    if version_fields != expected_versions:
        errors.append(
            f"{label}.expectedVersionFields: must exactly equal CAS-derived {sorted(expected_versions)}"
        )
    entity_ids = _contract_indexes(contract)["entities"]
    writes = set(binding.get("sameTransactionWriteEntityIds", [])) if isinstance(binding.get("sameTransactionWriteEntityIds"), list) else set()
    unknown_entities = sorted(writes - entity_ids)
    if unknown_entities:
        errors.append(f"{label}.sameTransactionWriteEntityIds: unknown entities {unknown_entities}")
    machine_entity = parent_machine.get("entityId")
    if machine_entity not in writes:
        errors.append(f"{label}.sameTransactionWriteEntityIds: must include FSM entity {machine_entity}")
    failures = binding.get("failureOutcomes")
    if not isinstance(failures, list) or not failures:
        errors.append(f"{label}.failureOutcomes: expected non-empty array")
        failures = []
    expected_failure_pairs: set[tuple[str, str]] = set()
    for operation_id in expected_operations:
        operation = operations_by_id.get(operation_id)
        if not isinstance(operation, Mapping):
            continue
        for reason in transition.get("failureReasonCodes", []):
            if reason in operation.get("failureReasonCodes", []):
                expected_failure_pairs.add((operation_id, reason))
    uncovered_reasons = set(transition.get("failureReasonCodes", [])) - {
        reason for _, reason in expected_failure_pairs
    }
    if uncovered_reasons:
        errors.append(
            f"{label}: portable transition failure reasons lack an owning ordered operation {sorted(uncovered_reasons)}"
        )
    actual_failure_pairs: list[tuple[Any, Any]] = []
    nested_compensation: set[str] = set()
    valid_states = set(parent_machine.get("states", []))
    reason_registry = _contract_indexes(contract)["reasons"]
    for index, outcome in enumerate(failures):
        outcome_label = f"{label}.failureOutcomes[{index}]"
        _exact_keys(outcome, FAILURE_OUTCOME_FIELDS, outcome_label, errors)
        if not isinstance(outcome, Mapping):
            continue
        pair = (outcome.get("operationId"), outcome.get("reasonCode"))
        actual_failure_pairs.append(pair)
        if outcome.get("authoritativeState") not in valid_states:
            errors.append(f"{outcome_label}.authoritativeState: unknown FSM state")
        reason = reason_registry.get(outcome.get("reasonCode"))
        if reason is None:
            errors.append(f"{outcome_label}.reasonCode: unknown closed Reason")
        else:
            retry_policy = outcome.get("retryPolicy")
            if reason.get("retryable") is True and retry_policy not in {
                "RETRY_SAME_GENERATION",
                "NEW_RUN_GENERATION",
            }:
                errors.append(f"{outcome_label}.retryPolicy: retryable Reason requires a typed retry")
            if reason.get("retryable") is False and retry_policy in {
                "RETRY_SAME_GENERATION",
                "NEW_RUN_GENERATION",
            }:
                errors.append(f"{outcome_label}.retryPolicy: nonretryable Reason cannot retry")
        if (
            isinstance(outcome.get("reasonCode"), str)
            and any(token in outcome["reasonCode"] for token in ("UNCERTAIN", "UNVERIFIED"))
            and outcome.get("authoritativeState") == "FREE"
        ):
            errors.append(f"{outcome_label}: uncertain cleanup cannot map to FREE")
        if outcome.get("leaseClaimEffect") not in {
            "NO_LEASE_CREATED",
            "RETAIN_COMPLETE_SET",
            "REVOKE_COMPLETE_SET",
            "QUARANTINE_COMPLETE_SET",
        }:
            errors.append(f"{outcome_label}.leaseClaimEffect: unknown effect")
        if outcome.get("assignedIdEffect") not in {"NOT_PUBLISHED", "UNCHANGED", "CLEAR"}:
            errors.append(f"{outcome_label}.assignedIdEffect: unknown effect")
        if outcome.get("releaseGuardEffect") not in {"NOT_APPLICABLE", "RETAIN", "CONSUME"}:
            errors.append(f"{outcome_label}.releaseGuardEffect: unknown effect")
        if outcome.get("quarantineScope") not in {
            "NONE",
            "COMPLETE_ASSIGNMENT",
            "COMPLETE_OWNER_GROUP",
            "COMPLETE_RELOCATION_TARGET",
            "COMPLETE_REMEDIATION_SCOPE",
        }:
            errors.append(f"{outcome_label}.quarantineScope: unknown scope")
        nested = outcome.get("compensationTransitionIds")
        if isinstance(nested, list):
            _require_canonical_set_order(
                nested, f"{outcome_label}.compensationTransitionIds", errors
            )
            unknown = sorted(set(nested) - set(all_transitions))
            if unknown:
                errors.append(
                    f"{outcome_label}.compensationTransitionIds: unknown transitions {unknown}"
                )
            nested_compensation.update(nested)
    expected_failure_order = sorted(
        expected_failure_pairs,
        key=lambda item: canonical_json_bytes(list(item)),
    )
    if actual_failure_pairs != expected_failure_order:
        errors.append(
            f"{label}.failureOutcomes: exact ordered [operationId,reasonCode] pairs must be {expected_failure_order}"
        )
    compensation = set(binding.get("compensationTransitionIds", [])) if isinstance(binding.get("compensationTransitionIds"), list) else set()
    unknown_compensation = sorted(compensation - set(all_transitions))
    if unknown_compensation:
        errors.append(f"{label}.compensationTransitionIds: unknown transitions {unknown_compensation}")
    if compensation != nested_compensation:
        errors.append(
            f"{label}.compensationTransitionIds: must equal exact union of failure-outcome compensation"
        )
    if binding.get("successAssignedIdEffect") not in {"UNCHANGED", "PUBLISH", "CLEAR"}:
        errors.append(f"{label}.successAssignedIdEffect: unknown effect")
    projection = copy.deepcopy(dict(binding))
    projection.pop("bindingDigest", None)
    actual_digest = _canonical_digest(projection, f"{label} projection", errors)
    if actual_digest is not None and binding.get("bindingDigest") != actual_digest:
        errors.append(
            f"{label}.bindingDigest: declared {binding.get('bindingDigest')}, actual {actual_digest}"
        )


def _validate_mapping_entry_shape(
    entry: Any,
    root: Path,
    code_git: _GitView | None,
    evidence_git: _GitView | None,
    trust: _TrustContext | None,
    contract: Mapping[str, Any],
    label: str,
    errors: list[str],
) -> None:
    _exact_keys(entry, MAPPING_FIELDS, label, errors)
    if not isinstance(entry, Mapping):
        return
    status = entry.get("mappingStatus")
    disposition = entry.get("disposition")
    implementation = entry.get("implementationStatus")
    bindings = entry.get("targetBindings")
    tests = entry.get("targetTestBindings")
    if not isinstance(bindings, list):
        errors.append(f"{label}.targetBindings: expected array")
        bindings = []
    if not isinstance(tests, list):
        errors.append(f"{label}.targetTestBindings: expected array")
        tests = []
    for index, binding in enumerate(bindings):
        _validate_target_binding(
            binding,
            code_git,
            evidence_git,
            trust,
            f"{label}.targetBindings[{index}]",
            errors,
        )
    if not isinstance(entry.get("notes"), str):
        errors.append(f"{label}.notes: expected string")
    transition_binding = entry.get("transitionExecutionBinding")
    if entry.get("kind") == "TRANSITION" and status == "BOUND":
        _validate_transition_execution_binding(
            transition_binding, entry.get("contractItemId"), contract, f"{label}.transitionExecutionBinding", errors
        )
    elif transition_binding is not None:
        errors.append(f"{label}.transitionExecutionBinding: only a BOUND TRANSITION may carry this field")
    if status == "UNMAPPED":
        if (disposition, implementation) != ("UNMAPPED", "NOT_STARTED"):
            errors.append(f"{label}: UNMAPPED must be UNMAPPED/NOT_STARTED")
        if bindings or tests or transition_binding is not None or entry.get("conflict") is not None or entry.get("deferDecision") is not None:
            errors.append(f"{label}: UNMAPPED cannot carry bindings, tests, conflict, or defer evidence")
    elif status == "BOUND":
        if disposition not in {"REUSE", "EXTEND", "NEW"}:
            errors.append(f"{label}.disposition: BOUND requires REUSE, EXTEND, or NEW")
        if not bindings:
            errors.append(f"{label}.targetBindings: BOUND requires at least one binding")
        if entry.get("conflict") is not None or entry.get("deferDecision") is not None:
            errors.append(f"{label}: BOUND cannot carry conflict/defer evidence")
    elif status == "CONFLICT":
        if disposition != "CONFLICT":
            errors.append(f"{label}.disposition: CONFLICT mapping requires CONFLICT")
        conflict = entry.get("conflict")
        _exact_keys(conflict, CONFLICT_FIELDS, f"{label}.conflict", errors)
        if isinstance(conflict, Mapping):
            _is_digest(conflict.get("approvalEvidenceHash"), f"{label}.conflict.approvalEvidenceHash", errors)
        if entry.get("deferDecision") is not None:
            errors.append(f"{label}: CONFLICT cannot carry defer evidence")
    elif status == "DEFERRED":
        if entry.get("releaseTrack") != "FUTURE_SEPARATELY_QUALIFIED":
            errors.append(f"{label}.releaseTrack: only a future track may be deferred")
        if (disposition, implementation) != ("DEFERRED", "NOT_APPLICABLE_CURRENT_RELEASE"):
            errors.append(f"{label}: DEFERRED must be DEFERRED/NOT_APPLICABLE_CURRENT_RELEASE")
        if bindings or tests or entry.get("conflict") is not None:
            errors.append(f"{label}: DEFERRED cannot carry target bindings, tests, or conflict")
        _validate_defer_decision(entry.get("deferDecision"), root, f"{label}.deferDecision", errors)
    else:
        errors.append(f"{label}.mappingStatus: unknown status {status!r}")


def _validate_test_binding(
    binding: Any,
    *,
    contract_item_id: str | None,
    contract_kind: str | None,
    code_git: _GitView | None,
    evidence_git: _GitView | None,
    root: Path,
    contract: Mapping[str, Any],
    mapping: Mapping[str, Any],
    trust: _TrustContext | None,
    risks: set[str],
    label: str,
    errors: list[str],
) -> dict[str, Any]:
    local_error_count = len(errors)
    empty_coverage: dict[str, Any] = {
        "cases": set(),
        "testObligations": set(),
        "oracleClassesByCase": {},
    }
    _exact_keys(binding, TEST_BINDING_FIELDS, label, errors)
    if not isinstance(binding, Mapping):
        return empty_coverage
    if binding.get("contractItemId") != contract_item_id:
        errors.append(
            f"{label}.contractItemId: must equal parent mapping obligation {contract_item_id!r}"
        )
    if binding.get("testFileRepositoryAuthority") != "TARGET_CODE_C":
        errors.append(f"{label}.testFileRepositoryAuthority: expected TARGET_CODE_C")
    if binding.get("scenarioRepositoryAuthority") != "EVIDENCE_E":
        errors.append(f"{label}.scenarioRepositoryAuthority: expected EVIDENCE_E")
    if binding.get("testFileHashScope") != "GIT_BLOB_BYTES":
        errors.append(f"{label}.testFileHashScope: only GIT_BLOB_BYTES is authoritative")
    if binding.get("scenarioHashScope") != "GIT_BLOB_BYTES":
        errors.append(f"{label}.scenarioHashScope: only GIT_BLOB_BYTES is authoritative")
    map_commit = code_git.commit if code_git else None
    binding_commit = _normal_commit(binding.get("targetRepositoryCommit"), f"{label}.targetRepositoryCommit", errors)
    if map_commit is not None and binding_commit != map_commit:
        errors.append(f"{label}.targetRepositoryCommit: does not match integration-map commit")
    test_blob = (
        code_git.blob(binding.get("path"), f"{label}.path", errors)
        if code_git
        else None
    )
    _check_blob_hash(test_blob, binding.get("testFileSha256"), f"{label}.testFile", errors)
    symbol = binding.get("symbol")
    if test_blob is not None and isinstance(symbol, str) and symbol.encode("utf-8") not in test_blob:
        errors.append(f"{label}.symbol: {symbol!r} is absent from the pinned test blob")
    evidence_commit = _normal_commit(
        binding.get("evidenceRepositoryCommit"),
        f"{label}.evidenceRepositoryCommit",
        errors,
    )
    if evidence_git is not None and evidence_commit != evidence_git.commit:
        errors.append(
            f"{label}.evidenceRepositoryCommit: does not match integration-map evidence E"
        )
    scenario_blob = (
        evidence_git.blob(
            binding.get("scenarioPath"), f"{label}.scenarioPath", errors
        )
        if evidence_git
        else None
    )
    _check_blob_hash(scenario_blob, binding.get("scenarioSha256"), f"{label}.scenario", errors)
    case_ids = set(_unique_strings(binding.get("caseIds"), f"{label}.caseIds", errors))
    known_cases = _contract_indexes(contract)["cases"]
    unknown_cases = sorted(case_ids - known_cases)
    if unknown_cases:
        errors.append(f"{label}.caseIds: unknown closed Case IDs {unknown_cases}")
    if scenario_blob is None:
        return empty_coverage
    scenario = _load_json_bytes(scenario_blob, f"{label}.scenario", errors)
    if not isinstance(scenario, Mapping):
        return empty_coverage
    if scenario.get("definitionStatus") != "EXECUTED_PASS":
        errors.append(f"{label}.scenario: only EXECUTED_PASS is implementation evidence")
    if binding.get("scenarioId") != scenario.get("scenarioId"):
        errors.append(f"{label}.scenarioId: does not match scenario document")
    traceability = scenario.get("traceability")
    scenario_target = scenario.get("targetBinding")
    if isinstance(scenario_target, Mapping):
        exact_test_binding = {
            "testPath": binding.get("path"),
            "testSymbol": binding.get("symbol"),
            "testInterfaceHash": binding.get("testFileSha256"),
        }
        for field, expected in exact_test_binding.items():
            if scenario_target.get(field) != expected:
                errors.append(f"{label}.scenario.targetBinding.{field}: expected {expected!r}")
    scenario_case_id = scenario.get("caseId")
    if case_ids != {scenario_case_id}:
        errors.append(
            f"{label}.caseIds: one scenario binds exactly its own Case "
            f"{scenario_case_id!r}; aggregate Case claims are forbidden"
        )
    scenario_errors = _validate_scenario_document_core(
        scenario,
        contract,
        root=root,
        mapping_document=mapping,
        _code_git_view=code_git,
        _evidence_git_view=evidence_git,
        _trust_context=trust,
        _risk_ids=risks,
    )
    errors.extend(f"{label}.scenario: {item}" for item in scenario_errors)
    result = scenario.get("executionResult")
    if isinstance(result, Mapping):
        if binding.get("executionEvidenceIndexRecordSha256") != result.get("evidenceIndexRecordSha256"):
            errors.append(
                f"{label}.executionEvidenceIndexRecordSha256: does not match the signed scenario result"
            )
    if len(errors) != local_error_count or scenario.get("definitionStatus") != "EXECUTED_PASS":
        return empty_coverage
    traced_fields = {
        field: set(traceability.get(field, []))
        for field in (
            "canonicalizationProfileIds",
            "guardIds",
            "configIds",
            "migrationIds",
            "telemetryIds",
            "portIds",
            "operationIds",
            "entityIds",
            "stateMachineIds",
            "transitionIds",
            "testObligationIds",
            "parityObligationIds",
            "expectedReasonCodes",
        )
        if isinstance(traceability, Mapping)
    }
    direct_trace_field = {
        "PORT": "portIds",
        "OPERATION": "operationIds",
        "ENTITY": "entityIds",
        "STATE_MACHINE": "stateMachineIds",
        "TRANSITION": "transitionIds",
        "TEST": "testObligationIds",
        "PARITY_OBLIGATION": "parityObligationIds",
        "REASON": "expectedReasonCodes",
        "CANONICALIZATION": "canonicalizationProfileIds",
        "GUARD": "guardIds",
        "CONFIG": "configIds",
        "MIGRATION": "migrationIds",
        "TELEMETRY": "telemetryIds",
    }.get(contract_kind)
    typed_eligible = False
    if direct_trace_field is not None:
        typed_eligible = contract_item_id in traced_fields.get(direct_trace_field, set())
    elif contract_kind == "CAS_RULE":
        traced_cas_rules = {
            cas_rule_id
            for transition_id in traced_fields.get("transitionIds", set())
            if (
                transition_record := _contract_indexes(contract)["transitions"].get(
                    transition_id
                )
            )
            is not None
            for cas_rule_id in transition_record["transition"].get("casRuleIds", [])
        }
        typed_eligible = contract_item_id in traced_cas_rules
    elif contract_kind == "EQUIVALENCE":
        typed_eligible = (
            "TEST-DYNAMIC" in traced_fields.get("testObligationIds", set())
            and "OP-SOLVE-DYNAMIC" in traced_fields.get("operationIds", set())
        )
    if not typed_eligible:
        errors.append(
            f"{label}: scenario is unrelated to parent {contract_kind} "
            f"obligation {contract_item_id!r} under its typedCoverageRule"
        )
        return empty_coverage
    traced_tests = (
        set(traceability.get("testObligationIds", []))
        if isinstance(traceability, Mapping)
        else set()
    )
    oracle_classes = set(ORACLE_CATEGORY_FIELDS)
    iterations = result.get("iterationResults", []) if isinstance(result, Mapping) else []
    if not isinstance(iterations, list) or not iterations:
        oracle_classes.clear()
    else:
        for iteration in iterations:
            matrix = iteration.get("oracleResults") if isinstance(iteration, Mapping) else None
            present = {
                category
                for category in ORACLE_CATEGORY_FIELDS
                if isinstance(matrix, Mapping)
                and isinstance(matrix.get(category), list)
                and bool(matrix.get(category))
            }
            oracle_classes &= present
    return {
        "cases": {scenario_case_id},
        "testObligations": traced_tests,
        "oracleClassesByCase": {scenario_case_id: oracle_classes},
    }


def _mapping_core(
    mapping: Mapping[str, Any],
    contract: Mapping[str, Any],
    root: Path,
    errors: list[str],
    *,
    expect_baseline: bool = False,
    trusted_root_digest: str | None = None,
    external_rollback_anchor: Any | None = None,
    external_catalog_anchor: Any | None = None,
    trust_anchor_freshness_envelope: Any | None = None,
    catalog_anchor_freshness_envelope: Any | None = None,
    verifier_nonce: str | None = None,
) -> None:
    _exact_keys(mapping, MAP_FIELDS, "integration map", errors)
    _validate_normative_source_closure(contract, root, errors)
    _validate_state_machine_contract(contract, errors)
    if mapping.get("schemaVersion") != 1:
        errors.append("integration map.schemaVersion: expected 1")
    for field in ("mapId", "mappingCoreId"):
        if not isinstance(mapping.get(field), str) or not mapping.get(field):
            errors.append(f"integration map.{field}: expected non-empty stable ID")
    source = mapping.get("sourceContract")
    _exact_keys(source, SOURCE_CONTRACT_FIELDS, "sourceContract", errors)
    if isinstance(source, Mapping):
        expected_source = {
            "path": "contracts/directpath-portable-control-contract.json",
            "contractId": contract.get("contractId"),
            "revision": contract.get("revision"),
        }
        for field, expected in expected_source.items():
            if source.get(field) != expected:
                errors.append(f"sourceContract.{field}: expected {expected!r}")
        contract_digest = _canonical_digest(contract, "portable contract", errors)
        if source.get("sha256") is not None and contract_digest is not None and source.get("sha256") != contract_digest:
            errors.append(
                f"sourceContract.sha256: declared {source.get('sha256')}, actual {contract_digest}"
            )
    repository = mapping.get("targetRepository")
    _exact_keys(repository, TARGET_REPOSITORY_FIELDS, "targetRepository", errors)
    evidence_repository = mapping.get("evidenceRepository")
    if evidence_repository is not None:
        _exact_keys(
            evidence_repository,
            EVIDENCE_REPOSITORY_FIELDS,
            "evidenceRepository",
            errors,
        )
    topology = mapping.get("artifactTopology")
    _exact_keys(topology, ARTIFACT_TOPOLOGY_FIELDS, "artifactTopology", errors)
    expected_topology = {
        "graph": (
            "TARGET_CODE_C_TO_MAPPING_CORE_M_TO_CATALOG_AND_EVIDENCE_CONTENT_"
            "TO_EXTERNAL_CATALOG_ANCHOR_A_TO_EVIDENCE_REVISION_E_TO_"
            "DETACHED_FINAL_MAP"
        ),
        "mappingCoreStorage": "DETACHED_CONTENT_ADDRESS",
        "catalogAnchorStorage": "EXTERNAL_MONOTONIC_AUTHORITY_NOT_IN_C_OR_E_OR_MAP",
        "finalMapStorage": "DETACHED_NOT_IN_C_OR_E",
        "selfReferencePolicy": "REJECT_ANY_BLOB_EMBEDDING_ITS_CONTAINING_REVISION",
    }
    if isinstance(topology, Mapping):
        for field, expected in expected_topology.items():
            if topology.get(field) != expected:
                errors.append(f"artifactTopology.{field}: expected {expected!r}")
    statuses = mapping.get("statusAxes")
    _exact_keys(statuses, STATUS_FIELDS, "statusAxes", errors)
    axes: dict[str, bool] = {}
    if isinstance(statuses, Mapping):
        for field in STATUS_FIELDS:
            value = statuses.get(field)
            if type(value) is not bool:
                errors.append(f"statusAxes.{field}: expected JSON boolean")
            else:
                axes[field] = value
        if axes.get("PORTABLE_SPEC_READY") is not True:
            errors.append("statusAxes.PORTABLE_SPEC_READY: portable contract requires true")
        if axes.get("PRODUCT_IMPLEMENTED") and not axes.get("TARGET_CODE_MAPPED"):
            errors.append("statusAxes: PRODUCT_IMPLEMENTED implies TARGET_CODE_MAPPED")
        if axes.get("QUALIFIED") and not axes.get("PRODUCT_IMPLEMENTED"):
            errors.append("statusAxes: QUALIFIED implies PRODUCT_IMPLEMENTED")
    if expect_baseline and any(
        axes.get(field) for field in ("TARGET_CODE_MAPPED", "PRODUCT_IMPLEMENTED", "QUALIFIED")
    ):
        errors.append("baseline: target mapping, product implementation, and qualification must remain false")
    mappings = mapping.get("mappings")
    if not isinstance(mappings, list):
        errors.append("mappings: expected ordered array")
        mappings = []
    try:
        expected_items = derive_mapping_items(contract)
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(f"portable contract mappingSurface: cannot derive: {exc}")
        expected_items = []
    mapping_surface = contract.get("mappingSurface")
    if not isinstance(mapping_surface, Mapping):
        errors.append("portable contract.mappingSurface: expected object")
        mapping_surface = {}
    if mapping_surface.get("verificationMatrixVersion") != 1:
        errors.append("portable contract.mappingSurface.verificationMatrixVersion: expected 1")
    declared_matrix = mapping_surface.get("verificationMatrix")
    if not isinstance(declared_matrix, list):
        errors.append("portable contract.mappingSurface.verificationMatrix: expected array")
        declared_matrix = []
    try:
        expected_matrix = _derive_verification_matrix(
            contract, expected_items, root
        )
    except (KeyError, TypeError, ValueError, CanonicalizationError) as exc:
        errors.append(f"portable contract verificationMatrix: cannot derive: {exc}")
        expected_matrix = []
    for index, row in enumerate(declared_matrix):
        _exact_keys(
            row,
            VERIFICATION_ROW_FIELDS,
            f"verificationMatrix[{index}]",
            errors,
        )
        if not isinstance(row, Mapping):
            continue
        for field in (
            "requiredTestObligationIds",
            "requiredCaseIds",
            "requiredOracleClasses",
        ):
            _unique_strings(row.get(field), f"verificationMatrix[{index}].{field}", errors)
        projection = dict(row)
        projection.pop("requirementDigest", None)
        digest = _canonical_digest(
            projection, f"verificationMatrix[{index}] digest projection", errors
        )
        if digest is not None and row.get("requirementDigest") != digest:
            errors.append(
                f"verificationMatrix[{index}].requirementDigest: declared "
                f"{row.get('requirementDigest')}, actual {digest}"
            )
    if declared_matrix != expected_matrix:
        mismatch = next(
            (
                index
                for index, (declared, expected) in enumerate(
                    zip(declared_matrix, expected_matrix)
                )
                if declared != expected
            ),
            min(len(declared_matrix), len(expected_matrix)),
        )
        errors.append(
            "portable contract.mappingSurface.verificationMatrix: independent "
            f"derivation mismatch at index {mismatch}"
        )
    actual_items = [
        {
            "contractItemId": item.get("contractItemId") if isinstance(item, Mapping) else None,
            "kind": item.get("kind") if isinstance(item, Mapping) else None,
            "releaseTrack": item.get("releaseTrack") if isinstance(item, Mapping) else None,
        }
        for item in mappings
    ]
    if actual_items != expected_items:
        mismatch = next(
            (
                index
                for index, (actual, expected) in enumerate(zip(actual_items, expected_items))
                if actual != expected
            ),
            min(len(actual_items), len(expected_items)),
        )
        errors.append(
            f"mappings: closed ordered surface mismatch at index {mismatch}; "
            f"expected {len(expected_items)} items, found {len(actual_items)}"
        )
    for index, item in enumerate(mappings):
        if not isinstance(item, Mapping):
            continue
        expected_digest = (
            expected_matrix[index].get("requirementDigest")
            if index < len(expected_matrix)
            else None
        )
        if item.get("verificationRequirementDigest") != expected_digest:
            errors.append(
                f"mappings[{index}].verificationRequirementDigest: expected "
                f"{expected_digest!r} from the independent verification matrix"
            )
    scenario_projection_digest = _canonical_digest(
        _scenario_binding_projection(mapping), "scenarioBindingDigest projection", errors
    )
    map_projection_digest = _canonical_digest(
        _map_approval_projection(mapping), "mapDigest projection", errors
    )
    for field, actual in (
        ("scenarioBindingDigest", scenario_projection_digest),
        ("mapDigest", map_projection_digest),
    ):
        declared = mapping.get(field)
        if declared is not None:
            _is_digest(declared, field, errors)
            if actual is not None and declared != actual:
                errors.append(f"{field}: declared {declared}, actual {actual}")
    need_code_git = bool(
        axes.get("TARGET_CODE_MAPPED")
        or any(
            isinstance(item, Mapping)
            and (item.get("targetBindings") or item.get("targetTestBindings"))
            for item in mappings
        )
    )
    completion_claims = mapping.get("completionEvidence")
    need_evidence_git = bool(
        mapping.get("trustPolicy") is not None
        or mapping.get("approvals")
        or axes.get("TARGET_CODE_MAPPED")
        or axes.get("PRODUCT_IMPLEMENTED")
        or axes.get("QUALIFIED")
        or (
            isinstance(completion_claims, Mapping)
            and any(value is not None for value in completion_claims.values())
        )
        or any(
            isinstance(item, Mapping)
            and (item.get("targetBindings") or item.get("targetTestBindings"))
            for item in mappings
        )
    )
    code_git: _GitView | None = None
    if need_code_git:
        if isinstance(repository, Mapping):
            code_git = _GitView(root, repository, errors, "targetRepository")
        else:
            errors.append("targetRepository: required for bound state")
    evidence_git: _GitView | None = None
    if need_evidence_git:
        if isinstance(evidence_repository, Mapping):
            evidence_git = _GitView(
                root,
                evidence_repository,
                errors,
                "evidenceRepository",
            )
            forbidden_claims: list[bytes] = []
            final_map_digest = mapping.get("mapDigest")
            if isinstance(final_map_digest, str) and final_map_digest:
                forbidden_claims.append(final_map_digest.encode("ascii"))
            evidence_git.forbidden_blob_claims = tuple(forbidden_claims)
        else:
            errors.append("evidenceRepository: required for evidence-bound state")
    if (
        code_git is not None
        and evidence_git is not None
        and code_git.commit is not None
        and code_git.commit == evidence_git.commit
    ):
        errors.append(
            "artifactTopology: evidence revision E must be content-distinct from "
            "target-code revision C; checkout aliases/clones do not create a new revision"
        )
    raw_approvals = mapping.get("approvals")
    need_trust = bool(
        mapping.get("trustPolicy") is not None
        or raw_approvals
        or axes.get("TARGET_CODE_MAPPED")
    )
    trust: _TrustContext | None = None
    if need_trust:
        trust = _load_trust_context(
            mapping,
            evidence_git,
            root,
            errors,
            trusted_root_digest=trusted_root_digest,
            external_rollback_anchor=external_rollback_anchor,
            trust_anchor_freshness_envelope=trust_anchor_freshness_envelope,
            verifier_nonce=verifier_nonce,
            code_git=code_git,
        )
    for index, item in enumerate(mappings):
        _validate_mapping_entry_shape(
            item,
            root,
            code_git,
            evidence_git,
            trust,
            contract,
            f"mappings[{index}]",
            errors,
        )
    override_identities = {
        (item.get("kind"), item.get("contractItemId"))
        for item in contract.get("mappingSurface", {}).get("releaseTrackOverrides", [])
        if isinstance(item, Mapping) and item.get("currentReleaseDisposition") == "DEFERRED"
    }
    for index, item in enumerate(mappings):
        if not isinstance(item, Mapping):
            continue
        identity = (item.get("kind"), item.get("contractItemId"))
        if item.get("mappingStatus") == "DEFERRED" and identity not in override_identities:
            errors.append(f"mappings[{index}]: DEFERRED lacks a contract release-track override")
        if expect_baseline and identity in override_identities and item.get("mappingStatus") != "DEFERRED":
            errors.append(f"baseline: mappings[{index}] governed future item must remain authority-backed DEFERRED")
    completion = mapping.get("completionEvidence")
    _exact_keys(completion, COMPLETION_FIELDS, "completionEvidence", errors)
    approvals = mapping.get("approvals")
    if not isinstance(approvals, list):
        errors.append("approvals: expected array")
        approvals = []
    if len(approvals) > 4:
        errors.append("approvals: at most one approval per governed role")
    roles: list[str] = []
    for index, approval in enumerate(approvals):
        label = f"approvals[{index}]"
        _exact_keys(approval, APPROVAL_FIELDS, label, errors)
        if not isinstance(approval, Mapping):
            continue
        role = approval.get("role")
        if role not in {"TARGET_ARCHITECT", "SECURITY", "TEST", "PRODUCT_RELEASE"}:
            errors.append(f"{label}.role: unknown approval role")
        else:
            roles.append(role)
        if approval.get("decision") not in {"APPROVE", "REJECT"}:
            errors.append(f"{label}.decision: expected APPROVE or REJECT")
        for field in ("evidenceHash", "trustKeyRingDigest", "approvalDigest"):
            _is_digest(approval.get(field), f"{label}.{field}", errors)
        if trust is not None:
            resolved_key = trust.keys.get(approval.get("keyId"))
            if isinstance(resolved_key, Mapping) and approval.get(
                "identity"
            ) != resolved_key.get("principalId"):
                errors.append(
                    f"{label}.identity: must byte-equal signer key principalId"
                )
    if len(roles) != len(set(roles)):
        errors.append("approvals: duplicate governed role")
    separated_approvals = [
        item
        for item in approvals
        if isinstance(item, Mapping)
        and item.get("role") in {"TARGET_ARCHITECT", "SECURITY", "TEST"}
    ]
    for field in ("keyId", "identity"):
        values = [item.get(field) for item in separated_approvals]
        if any(not isinstance(value, str) or not value for value in values):
            errors.append(f"approvals: every separated-duty approval requires a non-empty {field}")
        if len(values) != len(set(values)):
            errors.append(
                f"approvals: TARGET_ARCHITECT, SECURITY, and TEST must use distinct {field} values"
            )
    if expect_baseline:
        if mapping.get("mapDigest") is not None or mapping.get("scenarioBindingDigest") is not None:
            errors.append("baseline: mapDigest and scenarioBindingDigest must remain null")
        if mapping.get("trustPolicy") is not None:
            errors.append("baseline: trustPolicy must remain null until a target is pinned")
        if approvals:
            errors.append("baseline: approvals must be empty")
        if isinstance(repository, Mapping) and any(value is not None for value in repository.values()):
            errors.append("baseline: every targetRepository field must remain null")
        if evidence_repository is not None:
            errors.append("baseline: evidenceRepository must remain null")
        if isinstance(completion, Mapping) and any(value is not None for value in completion.values()):
            errors.append("baseline: completionEvidence fields must remain null")
        for index, item in enumerate(mappings):
            if not isinstance(item, Mapping):
                continue
            identity = (item.get("kind"), item.get("contractItemId"))
            expected_status = "DEFERRED" if identity in override_identities else "UNMAPPED"
            if item.get("mappingStatus") != expected_status:
                errors.append(
                    f"baseline: mappings[{index}].mappingStatus must be {expected_status}"
                )
    subject_digest = map_projection_digest
    for index, approval in enumerate(approvals):
        if not isinstance(approval, Mapping):
            continue
        label = f"approvals[{index}]"
        if subject_digest is not None and approval.get("evidenceHash") != subject_digest:
            errors.append(f"{label}.evidenceHash: does not equal the exact mapDigest projection")
        role = approval.get("role") if isinstance(approval.get("role"), str) else "INVALID_ROLE"
        _verify_signed_envelope(
            approval,
            digest_field="approvalDigest",
            signature_field="signature",
            signer_field="keyId",
            signed_time_field="decidedAt",
            domain="QMAN-DIRECTPATH/INTEGRATION-APPROVAL/V1",
            required_role=role,
            trust=trust,
            label=label,
            errors=errors,
        )
    if isinstance(completion, Mapping):
        for field, descriptor in completion.items():
            if descriptor is not None:
                expected_schema_ref = COMPLETION_SCHEMA_REFS.get(field)
                if expected_schema_ref is None:
                    errors.append(
                        f"completionEvidence.{field}: no fixed normative schema is registered"
                    )
                else:
                    completion_blob = _typed_artifact_from_git(
                        descriptor,
                        evidence_git,
                        root,
                        f"completionEvidence.{field}",
                        errors,
                        expected_schema_ref=expected_schema_ref,
                    )
                    report_type = {
                        "mappingCoverageReport": "MAPPING_COVERAGE_REPORT",
                        "implementationTestReport": "IMPLEMENTATION_TEST_REPORT",
                        "conflictRegister": "CONFLICT_REGISTER",
                    }.get(field)
                    if report_type is not None and isinstance(descriptor, Mapping):
                        _validate_integration_report(
                            completion_blob,
                            descriptor,
                            report_type,
                            mapping,
                            contract,
                            root,
                            code_git,
                            evidence_git,
                            trust,
                            f"completionEvidence.{field}",
                            errors,
                        )
    risks = _load_risk_ids(root, errors)
    test_coverage_by_mapping: dict[int, dict[str, Any]] = {}
    for index, item in enumerate(mappings):
        if not isinstance(item, Mapping):
            continue
        covered_cases: set[str] = set()
        covered_test_obligations: set[str] = set()
        covered_oracles_by_case: dict[str, set[str]] = {}
        binding_identities: set[tuple[Any, Any, Any]] = set()
        tests = item.get("targetTestBindings")
        if isinstance(tests, list):
            for test_index, binding in enumerate(tests):
                if isinstance(binding, Mapping):
                    identity = (
                        binding.get("scenarioPath"),
                        binding.get("scenarioId"),
                        tuple(binding.get("caseIds", []))
                        if isinstance(binding.get("caseIds"), list)
                        else None,
                    )
                    if identity in binding_identities:
                        errors.append(
                            f"mappings[{index}].targetTestBindings[{test_index}]: "
                            "duplicate scenario binding identity"
                        )
                    binding_identities.add(identity)
                coverage = _validate_test_binding(
                    binding,
                    contract_item_id=(
                        item.get("contractItemId")
                        if isinstance(item.get("contractItemId"), str)
                        else None
                    ),
                    contract_kind=(
                        item.get("kind")
                        if isinstance(item.get("kind"), str)
                        else None
                    ),
                    code_git=code_git,
                    evidence_git=evidence_git,
                    root=root,
                    contract=contract,
                    mapping=mapping,
                    trust=trust,
                    risks=risks,
                    label=f"mappings[{index}].targetTestBindings[{test_index}]",
                    errors=errors,
                )
                covered_cases.update(coverage["cases"])
                covered_test_obligations.update(coverage["testObligations"])
                for case_id, oracle_classes in coverage["oracleClassesByCase"].items():
                    covered_oracles_by_case.setdefault(case_id, set()).update(
                        oracle_classes
                    )
        test_coverage_by_mapping[index] = {
            "cases": covered_cases,
            "testObligations": covered_test_obligations,
            "oracleClassesByCase": covered_oracles_by_case,
        }
        requirement = expected_matrix[index] if index < len(expected_matrix) else None
        if not isinstance(requirement, Mapping):
            continue
        required_cases = set(requirement.get("requiredCaseIds", []))
        required_tests = set(requirement.get("requiredTestObligationIds", []))
        required_oracles = set(requirement.get("requiredOracleClasses", []))
        unrelated_cases = covered_cases - required_cases
        if unrelated_cases:
            errors.append(
                f"mappings[{index}].targetTestBindings: Cases {sorted(unrelated_cases)} "
                "are outside the contract-owned verification row"
            )
        for case_id in covered_cases:
            observed_oracles = covered_oracles_by_case.get(case_id, set())
            if not required_oracles.issubset(observed_oracles):
                errors.append(
                    f"mappings[{index}].targetTestBindings: Case {case_id} lacks "
                    f"required oracle classes {sorted(required_oracles - observed_oracles)}"
                )
        if item.get("implementationStatus") == "VERIFIED":
            if covered_cases != required_cases:
                errors.append(
                    f"mappings[{index}].targetTestBindings: VERIFIED requires exact "
                    f"contract-owned Cases {sorted(required_cases)}"
                )
            if not required_tests.issubset(covered_test_obligations):
                errors.append(
                    f"mappings[{index}].targetTestBindings: VERIFIED lacks required "
                    "typed test obligations "
                    f"{sorted(required_tests - covered_test_obligations)}"
                )
    verified_cases = {
        case_id
        for index, coverage in test_coverage_by_mapping.items()
        if index < len(mappings)
        and isinstance(mappings[index], Mapping)
        and mappings[index].get("implementationStatus") == "VERIFIED"
        for case_id in coverage.get("cases", set())
    }
    for case_id in sorted(verified_cases):
        case_record = _load_case_record(root, case_id, errors)
        dependencies = (
            set(case_record.get("dependsOnCaseIds", []))
            if isinstance(case_record, Mapping)
            and isinstance(case_record.get("dependsOnCaseIds"), list)
            else set()
        )
        missing_dependencies = dependencies - verified_cases
        if missing_dependencies:
            errors.append(
                f"Case {case_id}: VERIFIED evidence lacks closed dependency Cases "
                f"{sorted(missing_dependencies)}"
            )
    if axes.get("TARGET_CODE_MAPPED"):
        if not isinstance(source, Mapping) or source.get("sha256") is None:
            errors.append("TARGET_CODE_MAPPED: sourceContract.sha256 is required")
        if mapping.get("scenarioBindingDigest") is None:
            errors.append("TARGET_CODE_MAPPED: scenarioBindingDigest is required")
        if mapping.get("mapDigest") is None:
            errors.append("TARGET_CODE_MAPPED: mapDigest is required")
        required_completion = {"mappingCoverageReport", "conflictRegister", "trustKeyRing"}
        for field in required_completion:
            if not isinstance(completion, Mapping) or completion.get(field) is None:
                errors.append(f"TARGET_CODE_MAPPED: completionEvidence.{field} is required")
        if not any(
            isinstance(item, Mapping)
            and item.get("role") == "TARGET_ARCHITECT"
            and item.get("decision") == "APPROVE"
            for item in approvals
        ):
            errors.append("TARGET_CODE_MAPPED: signed TARGET_ARCHITECT approval is required")
        for index, item in enumerate(mappings):
            if not isinstance(item, Mapping):
                continue
            status = item.get("mappingStatus")
            track = item.get("releaseTrack")
            if status == "UNMAPPED":
                errors.append(f"TARGET_CODE_MAPPED: mappings[{index}] remains UNMAPPED")
            if track == "CURRENT_RELEASE_REQUIRED" and status not in {"BOUND", "CONFLICT"}:
                errors.append(f"TARGET_CODE_MAPPED: mappings[{index}] current item is not BOUND/CONFLICT")
            if track == "FUTURE_SEPARATELY_QUALIFIED" and status not in {"BOUND", "CONFLICT", "DEFERRED"}:
                errors.append(f"TARGET_CODE_MAPPED: mappings[{index}] future item has invalid status")
            if status == "CONFLICT" and isinstance(completion, Mapping):
                conflict = item.get("conflict")
                register = completion.get("conflictRegister")
                if isinstance(conflict, Mapping) and isinstance(register, Mapping):
                    if conflict.get("approvalEvidenceHash") != register.get("sha256"):
                        errors.append(
                            f"TARGET_CODE_MAPPED: mappings[{index}] conflict approval is not bound to conflict register"
                        )
            if item.get("kind") == "TRANSITION" and status == "BOUND":
                transition_binding = item.get("transitionExecutionBinding")
                if not isinstance(transition_binding, Mapping):
                    errors.append(
                        f"TARGET_CODE_MAPPED: mappings[{index}] transitionExecutionBinding is required"
                    )
    if axes.get("PRODUCT_IMPLEMENTED"):
        for field in ("mappingCoverageReport", "implementationTestReport", "conflictRegister", "trustKeyRing"):
            if not isinstance(completion, Mapping) or completion.get(field) is None:
                errors.append(f"PRODUCT_IMPLEMENTED: completionEvidence.{field} is required")
        decisions = {
            item.get("role"): item.get("decision")
            for item in approvals
            if isinstance(item, Mapping)
        }
        for role in ("TARGET_ARCHITECT", "SECURITY", "TEST"):
            if decisions.get(role) != "APPROVE":
                errors.append(f"PRODUCT_IMPLEMENTED: signed {role} approval is required")
        if "REJECT" in decisions.values():
            errors.append("PRODUCT_IMPLEMENTED: a REJECT approval is present")
        for index, item in enumerate(mappings):
            if not isinstance(item, Mapping):
                continue
            track = item.get("releaseTrack")
            if track == "CURRENT_RELEASE_REQUIRED":
                if item.get("mappingStatus") != "BOUND" or item.get("implementationStatus") != "VERIFIED":
                    errors.append(f"PRODUCT_IMPLEMENTED: mappings[{index}] is not BOUND/VERIFIED")
                if not item.get("targetTestBindings"):
                    errors.append(f"PRODUCT_IMPLEMENTED: mappings[{index}] has no executable target test")
                if item.get("conflict") is not None or item.get("deferDecision") is not None:
                    errors.append(f"PRODUCT_IMPLEMENTED: mappings[{index}] carries conflict/defer state")
            elif item.get("mappingStatus") == "BOUND":
                if item.get("implementationStatus") != "VERIFIED" or not item.get("targetTestBindings"):
                    errors.append(f"PRODUCT_IMPLEMENTED: bound future mappings[{index}] is not independently VERIFIED")
            elif item.get("mappingStatus") != "DEFERRED":
                errors.append(f"PRODUCT_IMPLEMENTED: future mappings[{index}] must be BOUND or DEFERRED")
            if item.get("kind") == "TRANSITION" and item.get("mappingStatus") == "BOUND":
                transition_binding = item.get("transitionExecutionBinding")
                scenario_ids = {
                    test.get("scenarioId")
                    for test in item.get("targetTestBindings", [])
                    if isinstance(test, Mapping)
                }
                required_scenarios = (
                    set(transition_binding.get("crashTestScenarioIds", []))
                    if isinstance(transition_binding, Mapping)
                    else set()
                )
                if not required_scenarios or not required_scenarios.issubset(scenario_ids):
                    errors.append(
                        f"PRODUCT_IMPLEMENTED: mappings[{index}] lacks every declared transition crash scenario"
                    )
    if axes.get("QUALIFIED"):
        if not isinstance(completion, Mapping) or completion.get("qualificationEvidenceIndex") is None:
            errors.append("QUALIFIED: qualificationEvidenceIndex is required")
        if not any(
            isinstance(item, Mapping)
            and item.get("role") == "PRODUCT_RELEASE"
            and item.get("decision") == "APPROVE"
            for item in approvals
        ):
            errors.append("QUALIFIED: signed PRODUCT_RELEASE approval is required")
        if isinstance(completion, Mapping) and completion.get("qualificationEvidenceIndex") is not None:
            _validate_qualification_release(
                completion["qualificationEvidenceIndex"],
                code_git,
                evidence_git,
                root,
                contract,
                trust,
                errors,
                mapping,
                external_catalog_anchor,
                catalog_anchor_freshness_envelope,
                verifier_nonce,
            )


def validate_mapping_document(
    mapping_document: Any,
    contract_document: Any,
    root: str | os.PathLike[str] | Path = ".",
    *,
    expect_baseline: bool = False,
    trusted_root_digest: str | None = None,
    external_rollback_anchor: Any | None = None,
    external_catalog_anchor: Any | None = None,
    trust_anchor_freshness_envelope: Any | None = None,
    catalog_anchor_freshness_envelope: Any | None = None,
    verifier_nonce: str | None = None,
) -> list[str]:
    """Validate an integration map and every proof it claims.

    A false status axis is allowed while integration is in progress.  A true
    axis is accepted only when its target artifacts, tests, signatures, and
    dependent lower axes are proven.
    """

    errors: list[str] = []
    try:
        root_path = Path(root).resolve(strict=True)
    except OSError as exc:
        return [f"repository root: cannot resolve {root}: {exc}"]
    mapping = _coerce_document(mapping_document, "integration map", errors)
    contract = _coerce_document(contract_document, "portable contract", errors)
    if not isinstance(mapping, Mapping) or not isinstance(contract, Mapping):
        return errors
    try:
        _mapping_core(
            mapping,
            contract,
            root_path,
            errors,
            expect_baseline=expect_baseline,
            trusted_root_digest=trusted_root_digest,
            external_rollback_anchor=external_rollback_anchor,
            external_catalog_anchor=external_catalog_anchor,
            trust_anchor_freshness_envelope=trust_anchor_freshness_envelope,
            catalog_anchor_freshness_envelope=catalog_anchor_freshness_envelope,
            verifier_nonce=verifier_nonce,
        )
    except Exception as exc:  # A malformed claim must fail closed, never crash a release gate.
        errors.append(f"integration map: unexpected semantic validation failure: {type(exc).__name__}: {exc}")
    return errors


CASE_CONTRACT_REGISTRY_PATH = "contracts/directpath-acceptance-case-contracts.json"
CASE_CONTRACT_SCHEMA_REF = "contracts/directpath-acceptance-case-contract.schema.json"
CASE_CONTRACT_ORACLE_CLASSES = [
    "authoritativeWrites",
    "cleanup",
    "finalStates",
    "idempotencyOracle",
    "immediateResults",
    "mustNotOccur",
    "mustOccur",
    "physicalOracle",
]


def _case_design_rows(root: Path, errors: list[str]) -> list[dict[str, str]]:
    """Parse the exact 101-row design matrix without trusting the generator."""

    path = root / "qemu-static-dynamic-directpath-design.md"
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
        body = text.split("## 19.", 1)[1].split("## 20.", 1)[0]
    except (OSError, UnicodeDecodeError, IndexError) as exc:
        errors.append(f"Case contract design matrix: cannot read section 19: {exc}")
        return []
    rows: list[dict[str, str]] = []
    for line_number, line in enumerate(body.splitlines(), 1):
        if re.match(r"^\|\s*[COSDMF]\d{2}[a-z]?\s*\|", line) is None:
            continue
        columns = [part.strip() for part in line.strip().strip("|").split("|")]
        if len(columns) != 4:
            errors.append(
                "Case contract design matrix: row "
                f"{line_number} must contain exactly four columns"
            )
            continue
        case_id, title, pass_condition, source_evidence = columns
        row = {
            "caseId": case_id,
            "title": title,
            "passCondition": pass_condition,
            "sourceEvidence": source_evidence,
        }
        try:
            canonical_json_bytes(row)
        except (CanonicalizationError, TypeError, ValueError) as exc:
            errors.append(f"Case contract design matrix {case_id}: {exc}")
        rows.append(row)
    ids = [row["caseId"] for row in rows]
    if len(rows) != 101 or len(set(ids)) != 101:
        errors.append(
            "Case contract design matrix: section 19 must contain exactly 101 "
            f"unique Cases, found {len(rows)} rows/{len(set(ids))} IDs"
        )
    return rows


def _case_definition_records(
    root: Path, errors: list[str]
) -> dict[str, tuple[Mapping[str, Any], str, str]]:
    result: dict[str, tuple[Mapping[str, Any], str, str]] = {}
    directory = root / "acceptance" / "cases"
    for path in sorted(directory.glob("*.json")):
        try:
            blob = path.read_bytes()
        except OSError as exc:
            errors.append(f"Case definition {path}: cannot read: {exc}")
            continue
        relative = path.relative_to(root).as_posix()
        document = _load_json_bytes(blob, f"Case definition {relative}", errors)
        if not isinstance(document, Mapping):
            continue
        records = document.get("records", [document])
        if not isinstance(records, list):
            errors.append(f"Case definition {relative}.records: expected array")
            continue
        for index, record in enumerate(records):
            label = f"Case definition {relative}[{index}]"
            if not isinstance(record, Mapping):
                errors.append(f"{label}: expected object")
                continue
            case_id = record.get("id")
            if not isinstance(case_id, str) or not case_id:
                errors.append(f"{label}.id: expected non-empty string")
                continue
            if case_id in result:
                errors.append(f"{label}.id: duplicate Case {case_id}")
                continue
            result[case_id] = (record, relative, sha256(blob))
    if len(result) != 101:
        errors.append(
            "Case definitions: acceptance/cases must contain exactly 101 unique "
            f"records, found {len(result)}"
        )
    return result


def _case_assertion_oracle(statement: str) -> str:
    lowered = statement.casefold()
    if any(word in lowered for word in ("idempot", "replay", "重复", "重放")):
        return "idempotencyOracle"
    if any(
        word in lowered
        for word in (
            "cleanup",
            "release",
            "rollback",
            "quarant",
            "清理",
            "释放",
            "回滚",
            "隔离",
        )
    ):
        return "cleanup"
    if any(
        word in lowered
        for word in (
            "must not",
            " never ",
            "reject",
            "deny",
            "without",
            "不得",
            "拒绝",
            "不能",
            "不可",
        )
    ):
        return "mustNotOccur"
    if any(
        word in lowered
        for word in (
            "commit",
            "lease",
            "resourceversion",
            "cas",
            "持久",
            "事务",
            "租约",
        )
    ):
        return "authoritativeWrites"
    if any(word in lowered for word in ("state", " free", "attached", "状态")):
        return "finalStates"
    return "physicalOracle"


def _case_fault_classes(text: str) -> list[str]:
    lowered = text.casefold()
    values: set[str] = set()
    if any(word in lowered for word in ("qemu start", "qemu 启动", "spawn qemu")):
        values.add("QEMU_START_FAILURE")
    if any(
        word in lowered
        for word in ("stale", "epoch", "generation", "版本漂移", "过期")
    ):
        values.add("STALE_AUTHORITY")
    if any(word in lowered for word in ("crash", "崩溃")):
        values.add("PROCESS_CRASH")
    if any(
        word in lowered
        for word in (
            "race",
            "concurrent",
            "duplicate",
            "replay",
            "idempot",
            "并发",
            "重复",
            "重放",
        )
    ):
        values.add("CONCURRENCY_REPLAY")
    if any(
        word in lowered
        for word in (
            "host unreachable",
            "host loss",
            "source loss",
            "主机不可达",
            "源主机丢失",
        )
    ):
        values.add("HOST_UNREACHABLE")
    if any(
        word in lowered
        for word in ("cleanup", "release", "rollback", "清理", "释放", "回滚")
    ) and any(
        word in lowered for word in ("fail", "uncertain", "error", "失败", "不确定")
    ):
        values.add("CLEAN_RELEASE_FAILURE")
    if "reset" in lowered and any(
        word in lowered
        for word in ("fail", "without", "unsafe", "拒绝", "失败", "不安全")
    ):
        values.add("RESET_FAILURE")
    return sorted(values)


def _case_artifact_schemas(text: str) -> list[str]:
    lowered = text.casefold()
    values = {
        "contracts/directpath-acceptance-scenario.schema.json",
        "contracts/directpath-execution-evidence-index.schema.json",
        "contracts/directpath-runner-manifest.schema.json",
    }
    if any(
        word in lowered
        for word in (
            "release",
            "cleanup",
            "rollback",
            "relocat",
            "释放",
            "清理",
            "回滚",
            "迁移",
        )
    ):
        values.update(
            {
                "contracts/directpath-clean-release-receipt.schema.json",
                "contracts/directpath-authority-entities.schema.json#/$defs/ENTITY-CLEAN-RELEASE-ACCEPTANCE",
            }
        )
    if any(
        word in lowered
        for word in ("qualif", "catalog", "supported", "hcl", "兼容", "认证")
    ):
        values.update(
            {
                "contracts/directpath-qualification-record.schema.json",
                "contracts/directpath-qualification-subject-manifest.schema.json",
            }
        )
    if any(
        word in lowered
        for word in ("identity", "bdf", "serial", "deviceuid", "身份", "设备标识")
    ):
        values.add("contracts/directpath-identity-v1.schema.json")
    return sorted(values)


def _case_required_artifact_schemas(
    definition: Mapping[str, Any],
    semantic_text: str,
    root: Path,
) -> list[str]:
    """Join heuristic defaults with an optional closed, explicit Case list."""

    derived = set(_case_artifact_schemas(semantic_text))
    explicit = definition.get("requiredArtifactSchemaRefs", [])
    if not isinstance(explicit, list) or any(
        not isinstance(item, str) or not item for item in explicit
    ):
        raise ValueError(
            f"Case {definition.get('id')} requiredArtifactSchemaRefs "
            "must be a string list"
        )
    if len(explicit) != len(set(explicit)):
        raise ValueError(
            f"Case {definition.get('id')} requiredArtifactSchemaRefs "
            "must be unique"
        )
    if explicit != sorted(explicit):
        raise ValueError(
            f"Case {definition.get('id')} requiredArtifactSchemaRefs "
            "must use ascending schema-ref order"
        )
    for schema_ref in explicit:
        schema_path = schema_ref.split("#", 1)[0]
        if not schema_path.startswith("contracts/"):
            raise ValueError(
                f"Case {definition.get('id')} schema ref must stay under "
                f"contracts/: {schema_ref}"
            )
        if not (root / schema_path).is_file():
            raise ValueError(
                f"Case {definition.get('id')} references missing schema "
                f"{schema_path}"
            )
    return sorted(derived.union(explicit))


CASE_EXPLICIT_TRACE_FIELDS = (
    "requiredPortIds",
    "requiredOperationIds",
    "requiredTransitionIds",
    "requiredEntityIds",
    "requiredReasonIds",
)


def _case_indexed_records(
    records: Sequence[Any], id_field: str, label: str
) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for index, record in enumerate(records):
        if not isinstance(record, Mapping):
            raise ValueError(f"{label}[{index}] is not an object")
        item_id = record.get(id_field)
        if not isinstance(item_id, str) or not item_id:
            raise ValueError(f"{label}[{index}].{id_field} is not a non-empty string")
        if item_id in result:
            raise ValueError(f"{label} contains duplicate {id_field} {item_id}")
        result[item_id] = record
    return result


def _case_explicit_id_set(
    definition: Mapping[str, Any],
    field: str,
    known_ids: set[str],
    *,
    allow_empty: bool,
) -> list[str]:
    value = definition.get(field)
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise ValueError(f"Case {definition.get('id')} {field} must be a string list")
    if len(value) != len(set(value)):
        raise ValueError(f"Case {definition.get('id')} {field} must be unique")
    if value != sorted(value):
        raise ValueError(
            f"Case {definition.get('id')} {field} must use ascending ID order"
        )
    if not allow_empty and not value:
        raise ValueError(f"Case {definition.get('id')} {field} must not be empty")
    unknown = set(value) - known_ids
    if unknown:
        raise ValueError(
            f"Case {definition.get('id')} {field} references unknown IDs "
            f"{sorted(unknown)}"
        )
    return list(value)


def _case_required_trace(
    definition: Mapping[str, Any],
    *,
    derived_ports: list[str],
    port_by_id: Mapping[str, Mapping[str, Any]],
    operation_by_id: Mapping[str, Mapping[str, Any]],
    transition_by_id: Mapping[str, Mapping[str, Any]],
    entity_by_id: Mapping[str, Mapping[str, Any]],
    reason_by_id: Mapping[str, Mapping[str, Any]],
) -> tuple[list[str], list[str], list[str], list[str], list[str]]:
    """Independently resolve and close the optional Case trace override."""

    present = [
        field for field in CASE_EXPLICIT_TRACE_FIELDS if field in definition
    ]
    if present and len(present) != len(CASE_EXPLICIT_TRACE_FIELDS):
        missing = sorted(set(CASE_EXPLICIT_TRACE_FIELDS) - set(present))
        raise ValueError(
            f"Case {definition.get('id')} explicit trace is partial; missing {missing}"
        )

    if not present:
        required_ports = sorted(derived_ports)
        required_port_set = set(required_ports)
        required_operations = sorted(
            operation_id
            for operation_id, operation in operation_by_id.items()
            if operation.get("ownerPortId") in required_port_set
        )
        required_operation_set = set(required_operations)
        required_transitions = sorted(
            transition_id
            for transition_id, transition in transition_by_id.items()
            if set(transition.get("operationIds", [])) & required_operation_set
        )
        return (
            required_ports,
            required_operations,
            required_transitions,
            [],
            [],
        )

    required_ports = _case_explicit_id_set(
        definition, "requiredPortIds", set(port_by_id), allow_empty=False
    )
    required_operations = _case_explicit_id_set(
        definition,
        "requiredOperationIds",
        set(operation_by_id),
        allow_empty=False,
    )
    required_transitions = _case_explicit_id_set(
        definition,
        "requiredTransitionIds",
        set(transition_by_id),
        allow_empty=True,
    )
    required_entities = _case_explicit_id_set(
        definition, "requiredEntityIds", set(entity_by_id), allow_empty=False
    )
    required_reasons = _case_explicit_id_set(
        definition, "requiredReasonIds", set(reason_by_id), allow_empty=False
    )

    operation_set = set(required_operations)
    owner_ports = {
        operation_by_id[operation_id].get("ownerPortId")
        for operation_id in required_operations
    }
    if set(required_ports) != owner_ports:
        raise ValueError(
            f"Case {definition.get('id')} requiredPortIds must exactly equal "
            f"required operation owners {sorted(owner_ports)}"
        )
    for transition_id in required_transitions:
        referenced_operations = set(
            transition_by_id[transition_id].get("operationIds", [])
        )
        if not referenced_operations.issubset(operation_set):
            raise ValueError(
                f"Case {definition.get('id')} transition {transition_id} references "
                "operations outside requiredOperationIds "
                f"{sorted(referenced_operations - operation_set)}"
            )
    return (
        required_ports,
        required_operations,
        required_transitions,
        required_entities,
        required_reasons,
    )


def _derive_case_contract_registry(
    contract: Mapping[str, Any], root: Path, errors: list[str]
) -> Mapping[str, Any] | None:
    """Independently derive the complete immutable Case registry."""

    policy_path = root / "contracts" / "acceptance-policy.json"
    design_path = root / "qemu-static-dynamic-directpath-design.md"
    try:
        policy_blob = policy_path.read_bytes()
        design_blob = design_path.read_bytes()
    except OSError as exc:
        errors.append(f"Case contract sources: cannot read normative input: {exc}")
        return None
    policy = _load_json_bytes(policy_blob, "Case contract acceptance policy", errors)
    if not isinstance(policy, Mapping):
        return None
    rows = _case_design_rows(root, errors)
    definitions = _case_definition_records(root, errors)
    obligations = contract.get("acceptanceObligations", [])
    parity = contract.get("vmwareParityObligations", [])
    ports = contract.get("requiredPorts", [])
    operations = contract.get("backendNeutralOperations", [])
    transitions = [
        transition
        for machine in contract.get("stateMachines", [])
        if isinstance(machine, Mapping)
        for transition in machine.get("transitions", [])
        if isinstance(transition, Mapping)
    ]
    try:
        port_by_id = _case_indexed_records(ports, "id", "requiredPorts")
        operation_by_id = _case_indexed_records(
            operations, "id", "backendNeutralOperations"
        )
        transition_by_id = _case_indexed_records(
            transitions, "id", "stateMachine transitions"
        )
        entity_by_id = _case_indexed_records(
            contract.get("dataEntities", []), "id", "dataEntities"
        )
        reason_by_id = _case_indexed_records(
            contract.get("errorContract", {}).get("reasonCodes", []),
            "code",
            "errorContract.reasonCodes",
        )
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(f"Case contract portable indexes: {exc}")
        return None
    records: list[dict[str, Any]] = []
    for row in rows:
        case_id = row["caseId"]
        definition_tuple = definitions.get(case_id)
        if definition_tuple is None:
            errors.append(f"Case contract {case_id}: definition is missing")
            continue
        definition, definition_path, definition_file_digest = definition_tuple
        try:
            stories = sorted(definition["requiredTechStories"])
            story_set = set(stories)
            test_ids = sorted(
                item["id"]
                for item in obligations
                if isinstance(item, Mapping) and case_id in item.get("caseIds", [])
            )
            parity_ids = sorted(
                item["id"]
                for item in parity
                if isinstance(item, Mapping)
                and set(item.get("testObligationIds", [])) & set(test_ids)
            )
            derived_ports = sorted(
                item["id"]
                for item in ports
                if isinstance(item, Mapping)
                and set(item.get("techStoryIds", [])) & story_set
            )
            (
                required_ports,
                required_operations,
                required_transitions,
                required_entities,
                required_reasons,
            ) = _case_required_trace(
                definition,
                derived_ports=derived_ports,
                port_by_id=port_by_id,
                operation_by_id=operation_by_id,
                transition_by_id=transition_by_id,
                entity_by_id=entity_by_id,
                reason_by_id=reason_by_id,
            )
            semantic_parts = [
                row["title"],
                row["passCondition"],
                definition.get("title", ""),
                definition.get("blocker", ""),
                *(definition.get("assertions") or []),
            ]
            semantic_text = "\n".join(
                value for value in semantic_parts if isinstance(value, str)
            )
            matrix_projection = {
                "section": "19",
                "title": row["title"],
                "passCondition": row["passCondition"],
                "sourceEvidence": row["sourceEvidence"],
            }
            matrix = {
                **matrix_projection,
                "rowDigest": sha256(canonical_json_bytes(matrix_projection)),
            }
            assertion_sources: list[tuple[str, str]] = [
                ("DESIGN_PASS_CONDITION", row["passCondition"])
            ]
            for statement in definition.get("assertions") or []:
                if statement != row["passCondition"]:
                    assertion_sources.append(("CASE_ASSERTION", statement))
            assertions: list[dict[str, Any]] = []
            counters: dict[str, int] = {}
            for source_kind, statement in assertion_sources:
                prefix = (
                    "PASS" if source_kind == "DESIGN_PASS_CONDITION" else "ASSERT"
                )
                counters[prefix] = counters.get(prefix, 0) + 1
                assertion_projection = {
                    "assertionId": f"{case_id}-{prefix}-{counters[prefix]:03d}",
                    "sourceKind": source_kind,
                    "statement": statement,
                    "statementSha256": sha256(statement.encode("utf-8")),
                    "requiredOracleClass": _case_assertion_oracle(statement),
                    "predicateEvaluator": "TARGET-PREDICATE-INTERFACE-V1",
                }
                assertions.append(
                    {
                        **assertion_projection,
                        "assertionDigest": sha256(
                            canonical_json_bytes(assertion_projection)
                        ),
                    }
                )
            classification = {
                "scope": definition["scope"],
                "status": definition["status"],
                "targetMilestone": definition["targetMilestone"],
                "proofBoundaryOrNull": definition.get("proofBoundary"),
                "riskIds": sorted(definition["riskIds"]),
                "techStoryIds": stories,
                "dependsOnCaseIds": sorted(definition["dependsOnCaseIds"]),
            }
            faults = _case_fault_classes(semantic_text)
            explicit_entity_reason_trace = (
                {
                    "requiredEntityIds": required_entities,
                    "requiredReasonIds": required_reasons,
                }
                if "requiredEntityIds" in definition
                else {}
            )
            record_projection = {
                "caseId": case_id,
                "definitionPath": definition_path,
                "definitionFileSha256": definition_file_digest,
                "definitionRecordSha256": sha256(
                    canonical_json_bytes(definition)
                ),
                "designMatrix": matrix,
                "classification": classification,
                "testObligationIds": test_ids,
                "parityObligationIds": parity_ids,
                "requiredPortIds": required_ports,
                "requiredOperationIds": required_operations,
                "requiredTransitionIds": required_transitions,
                **explicit_entity_reason_trace,
                "requiredFaultClasses": faults,
                "requiredArtifactSchemaRefs": _case_required_artifact_schemas(
                    definition,
                    semantic_text,
                    root,
                ),
                "requiredOracleClasses": CASE_CONTRACT_ORACLE_CLASSES,
                "minimumRepeat": 3 if faults else 1,
                "minimumDurationSeconds": (
                    300
                    if definition["status"] == "HARDWARE_BLOCKED"
                    else 10
                    if faults
                    else 1
                ),
                "assertions": assertions,
                "evidenceBoundary": {
                    "productClosureGrade": "E3-END-TO-END-PRODUCT",
                    "qualificationClosureGrade": "E4-PHYSICAL-QUALIFICATION",
                    "componentOrReferenceEvidenceMayCloseProduct": False,
                    "vmwareObservationMayCloseProduct": False,
                    "blockedCaseMayExecuteAsClosure": False,
                    "dependencyClosureRequired": True,
                },
            }
        except (KeyError, TypeError, ValueError, CanonicalizationError) as exc:
            errors.append(f"Case contract {case_id}: cannot derive: {exc}")
            continue
        projection_with_null = {**record_projection, "caseContractDigest": None}
        records.append(
            {
                **record_projection,
                "caseContractDigest": sha256(
                    canonical_json_bytes(projection_with_null)
                ),
            }
        )
    expected_count = policy.get("expectedCaseCount")
    if expected_count != 101 or expected_count != len(records):
        errors.append(
            "Case contract registry: acceptance policy and derived record count "
            f"must both equal 101 (policy={expected_count!r}, derived={len(records)})"
        )
    root_projection = {
        "schemaVersion": 1,
        "registryId": "QMAN-DIRECTPATH-ACCEPTANCE-CASE-CONTRACTS",
        "generationAlgorithm": "DERIVED-CLOSED-CASE-CONTRACT-V1",
        "portableContractId": contract.get("contractId"),
        "portableContractRevision": contract.get("revision"),
        "sourcePolicySha256": sha256(policy_blob),
        "sourceDesignSha256": sha256(design_blob),
        "oracleClasses": CASE_CONTRACT_ORACLE_CLASSES,
        "caseCount": len(records),
        "records": records,
    }
    return {
        **root_projection,
        "registryDigest": sha256(
            canonical_json_bytes({**root_projection, "registryDigest": None})
        ),
    }


def _load_case_contract_registry(
    contract: Mapping[str, Any], root: Path, errors: list[str]
) -> Mapping[str, Any] | None:
    path = root / CASE_CONTRACT_REGISTRY_PATH
    try:
        blob = path.read_bytes()
    except OSError as exc:
        errors.append(f"Case contract registry: cannot read {path}: {exc}")
        return None
    registry = _load_json_bytes(blob, "Case contract registry", errors)
    if not isinstance(registry, Mapping):
        return None
    _validate_closed_json_schema_instance(
        registry,
        root,
        CASE_CONTRACT_SCHEMA_REF,
        "Case contract registry",
        errors,
    )
    expected = _derive_case_contract_registry(contract, root, errors)
    if not isinstance(expected, Mapping):
        return None
    actual_records = registry.get("records")
    expected_records = expected.get("records")
    for field in set(expected) - {"records"}:
        if registry.get(field) != expected.get(field):
            errors.append(
                f"Case contract registry.{field}: does not equal independent derivation"
            )
    if not isinstance(actual_records, list):
        errors.append("Case contract registry.records: expected array")
    elif isinstance(expected_records, list):
        actual_ids = [
            item.get("caseId") if isinstance(item, Mapping) else None
            for item in actual_records
        ]
        expected_ids = [item.get("caseId") for item in expected_records]
        if actual_ids != expected_ids:
            errors.append(
                "Case contract registry.records: IDs/order do not equal design "
                "section 19"
            )
        actual_by_id = {
            item.get("caseId"): item
            for item in actual_records
            if isinstance(item, Mapping) and isinstance(item.get("caseId"), str)
        }
        for expected_record in expected_records:
            case_id = expected_record["caseId"]
            actual_record = actual_by_id.get(case_id)
            if not isinstance(actual_record, Mapping):
                errors.append(f"Case contract registry: missing derived Case {case_id}")
                continue
            differing = sorted(
                field
                for field in set(expected_record) | set(actual_record)
                if actual_record.get(field) != expected_record.get(field)
            )
            if differing:
                errors.append(
                    f"Case contract registry {case_id}: fields differ from independent "
                    f"derivation {differing}"
                )
        expected_by_id = {item["caseId"]: item for item in expected_records}
        contract_digests = [item.get("caseContractDigest") for item in expected_records]
        if len(contract_digests) != len(set(contract_digests)):
            errors.append("Case contract registry: duplicate caseContractDigest")
        assertion_ids: list[str] = []
        assertion_digests: list[str] = []
        for record in expected_records:
            case_id = record["caseId"]
            for assertion in record.get("assertions", []):
                if not isinstance(assertion, Mapping):
                    continue
                assertion_id = assertion.get("assertionId")
                assertion_digest = assertion.get("assertionDigest")
                if isinstance(assertion_id, str):
                    assertion_ids.append(assertion_id)
                if isinstance(assertion_digest, str):
                    assertion_digests.append(assertion_digest)
            classification = record.get("classification")
            dependencies = (
                classification.get("dependsOnCaseIds", [])
                if isinstance(classification, Mapping)
                else []
            )
            for dependency in dependencies:
                if dependency == case_id:
                    errors.append(
                        f"Case contract registry {case_id}: self dependency is forbidden"
                    )
                dependency_record = expected_by_id.get(dependency)
                if dependency_record is None:
                    errors.append(
                        f"Case contract registry {case_id}: unknown dependency {dependency!r}"
                    )
                    continue
                dependency_classification = dependency_record.get("classification")
                if (
                    isinstance(classification, Mapping)
                    and classification.get("scope") == "PRODUCT"
                    and (
                        not isinstance(dependency_classification, Mapping)
                        or dependency_classification.get("scope") != "PRODUCT"
                    )
                ):
                    errors.append(
                        f"Case contract registry {case_id}: PRODUCT dependency "
                        f"{dependency!r} is not PRODUCT scope"
                    )
        if len(assertion_ids) != len(set(assertion_ids)):
            errors.append("Case contract registry: duplicate assertionId")
        if len(assertion_digests) != len(set(assertion_digests)):
            errors.append("Case contract registry: duplicate assertionDigest")

        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(case_id: str, path_ids: list[str]) -> None:
            if case_id in visiting:
                cycle_start = path_ids.index(case_id) if case_id in path_ids else 0
                errors.append(
                    "Case contract registry: dependency cycle "
                    + " -> ".join(path_ids[cycle_start:] + [case_id])
                )
                return
            if case_id in visited:
                return
            visiting.add(case_id)
            record = expected_by_id.get(case_id)
            classification = record.get("classification") if record else None
            dependencies = (
                classification.get("dependsOnCaseIds", [])
                if isinstance(classification, Mapping)
                else []
            )
            for dependency in dependencies:
                if dependency in expected_by_id:
                    visit(dependency, path_ids + [case_id])
            visiting.remove(case_id)
            visited.add(case_id)

        for case_id in expected_by_id:
            visit(case_id, [])
    return expected


SCENARIO_FIELDS = {
    "schemaVersion",
    "definitionStatus",
    "scenarioId",
    "caseId",
    "title",
    "scope",
    "targetMilestone",
    "applicability",
    "traceability",
    "caseContractDigest",
    "casePredicateBindings",
    "preconditions",
    "steps",
    "expected",
    "artifacts",
    "cleanup",
    "execution",
    "targetBinding",
    "executionResult",
}
APPLICABILITY_FIELDS = {
    "platformProfileIds",
    "backendFamilies",
    "deviceTraitFamilies",
    "requiresPhysicalHardware",
}
TRACE_FIELDS = {
    "contractItemIds",
    "canonicalizationProfileIds",
    "guardIds",
    "configIds",
    "migrationIds",
    "telemetryIds",
    "techStoryIds",
    "riskIds",
    "portIds",
    "operationIds",
    "entityIds",
    "stateMachineIds",
    "transitionIds",
    "testObligationIds",
    "parityObligationIds",
    "expectedReasonCodes",
}
PRECONDITION_FIELDS = {"initialStates", "authority", "fixtures", "facts"}
AUTHORITY_FIELDS = {"snapshotEpoch", "resourceVersion", "hostEpoch", "runGeneration"}
FIXTURE_FIELDS = {"id", "kind", "digest"}
STEP_FIELDS = {"sequence", "actor", "operationId", "request", "expectedImmediateResult"}
CASE_PREDICATE_BINDING_FIELDS = {
    "assertionId",
    "assertionDigest",
    "oracleClass",
    "predicateEvaluator",
    "targetPredicateSymbolOrNull",
    "targetPredicateInterfaceHashOrNull",
}
FAULT_FIELDS = {"point", "faultClasses", "trigger", "effect", "scheduleBarrier"}
EXPECTED_FIELDS = {
    "finalStates",
    "reasonCode",
    "retryable",
    "mustOccur",
    "mustNotOccur",
    "authoritativeWrites",
    "physicalOracle",
    "idempotencyOracle",
}
WRITE_FIELDS = {"entityId", "mutation", "predicate"}
ARTIFACT_EXPECTATION_FIELDS = {
    "artifactType",
    "producer",
    "formatOrSchema",
    "hashRequired",
    "correlationFields",
}
CLEAN_RELEASE_ACCEPTANCE_FIELDS = {
    "acceptanceId",
    "acceptanceKind",
    "receiptId",
    "receiptDigest",
    "assignmentId",
    "runId",
    "oldRunGeneration",
    "relocationIdOrNull",
    "relocationGenerationOrNull",
    "sourceHostId",
    "expectedSourceHostEpoch",
    "expectedAuthorityEntityId",
    "expectedAuthorityResourceVersion",
    "expectedLeaseSetHash",
    "expectedLeaseBindings",
    "committedAuthorityResourceVersion",
    "leaseRevocationCommitVersion",
    "repositoryTransactionId",
    "idempotencyKey",
    "acceptedAt",
    "receiptExpiresAt",
    "controllerGeneration",
    "keyRingVersion",
    "repositorySignerKeyId",
    "acceptanceDigest",
    "signature",
}
CLEAN_RELEASE_ACCEPTANCE_LEASE_FIELDS = {
    "leaseId",
    "leaseVersion",
    "bundleId",
    "memberDeviceUids",
}
CLEANUP_FIELDS = {"required", "expectedStates", "proofRequired"}
EXECUTION_FIELDS = {
    "targetTestBindingRequired",
    "timeoutMs",
    "repeat",
    "concurrencySchedule",
    "faultPointPlan",
}
FAULT_POINT_PLAN_FIELDS = {"faultPointOrNull", "faultClasses", "repeat"}
SCENARIO_TARGET_FIELDS = {
    "repositoryId",
    "repositoryObjectFormat",
    "repositoryCommit",
    "portableContractSha256",
    "integrationMapId",
    "mappingCoreId",
    "integrationMapSha256",
    "artifactGraphPosition",
    "testPath",
    "testSymbol",
    "testInterfaceHash",
    "fixtureSetHash",
    "platformProfileDigest",
    "backendProfileDigest",
    "evidenceGrade",
    "qualificationRunIdOrNull",
    "qualificationRunRequestDigestOrNull",
    "qualificationRunRequestNonceDigestOrNull",
    "trustKeyRingPath",
    "trustKeyRingSha256",
    "runnerManifestPath",
    "runnerManifestSha256",
    "hashScope",
    "buildId",
}
EXECUTION_RESULT_FIELDS = {
    "runId",
    "verdict",
    "startedAt",
    "finishedAt",
    "targetRepositoryCommit",
    "evidenceGrade",
    "qualificationRunIdOrNull",
    "qualificationRunRequestDigestOrNull",
    "qualificationRunRequestNonceDigestOrNull",
    "scenarioInputSha256",
    "runnerSha256",
    "runnerManifestDigest",
    "runnerManifestPath",
    "iterationResults",
    "artifactInstances",
    "resultCanonicalization",
    "evidenceIndexRecordSha256",
    "executionEvidenceIndexDigest",
    "executionEvidenceIndexPath",
    "resultDigest",
    "keyRingVersion",
    "signerKeyId",
    "signature",
    "limitations",
}
ITERATION_FIELDS = {
    "iteration",
    "iterationRunId",
    "verdict",
    "startedAt",
    "finishedAt",
    "observedDurationSeconds",
    "faultPointOrNull",
    "faultClasses",
    "scheduleTraceArtifactHash",
    "barrierObservationArtifactHashes",
    "cleanupProofArtifactHash",
    "artifactHashes",
    "operationExchanges",
    "oracleResults",
    "casePredicateResults",
}
OPERATION_EXCHANGE_FIELDS = {
    "stepSequence",
    "operationId",
    "requestEnvelope",
    "resultEnvelope",
}
OPERATION_REQUEST_ENVELOPE_ARTIFACT_FIELDS = {
    "path",
    "sha256",
    "byteLength",
    "mediaType",
    "schemaRef",
    "schemaSha256",
    "envelopeHash",
    "payloadHash",
}
OPERATION_RESULT_ENVELOPE_ARTIFACT_FIELDS = {
    *OPERATION_REQUEST_ENVELOPE_ARTIFACT_FIELDS,
    "status",
    "reasonCodeOrNull",
    "retryable",
}
CASE_PREDICATE_RESULT_FIELDS = {
    "assertionId",
    "assertionDigest",
    "oracleClass",
    "verdict",
    "evidenceArtifactHashes",
}
ARTIFACT_INSTANCE_FIELDS = {"artifactType", "producer", "path", "sha256", "correlation"}
ARTIFACT_CORRELATION_FIELDS = {
    "scenarioId",
    "caseId",
    "scenarioRunId",
    "iterationRunId",
    "iteration",
    "faultPointOrNull",
    "commandIdOrNull",
    "assignmentIdOrNull",
    "runIdOrNull",
    "subjectBindings",
}
SUBJECT_BINDING_FIELDS = {"key", "value"}
CORRELATION_EXPECTATION_FIXED_FIELDS = {
    "scenarioId": "scenarioId",
    "caseId": "caseId",
    "scenarioRunId": "scenarioRunId",
    "iterationRunId": "iterationRunId",
    "iteration": "iteration",
    "faultPoint": "faultPointOrNull",
    "commandId": "commandIdOrNull",
    "assignmentId": "assignmentIdOrNull",
    "runId": "runIdOrNull",
}
SUBJECT_BINDING_KEY_RE = re.compile(r"^[a-z][a-zA-Z0-9._-]{0,127}$")
ORACLE_FIELDS = {"oracleId", "verdict", "observed", "evidenceArtifactHashes"}
ORACLE_CATEGORY_FIELDS = {
    "immediateResults",
    "finalStates",
    "mustOccur",
    "mustNotOccur",
    "authoritativeWrites",
    "physicalOracle",
    "idempotencyOracle",
    "cleanup",
}


def _validate_correlation_expectation_fields(
    value: Any, label: str, errors: list[str]
) -> list[str]:
    fields = _unique_strings(value, label, errors)
    _require_canonical_set_order(value, label, errors)
    for index, field in enumerate(fields):
        if field in CORRELATION_EXPECTATION_FIXED_FIELDS:
            continue
        if SUBJECT_BINDING_KEY_RE.fullmatch(field) is None:
            errors.append(
                f"{label}[{index}]: expected a closed first-class correlation name "
                "or a valid subjectBindings key"
            )
    return fields


def _subject_binding_map(
    value: Any, label: str, errors: list[str]
) -> dict[str, str]:
    if not isinstance(value, list):
        errors.append(f"{label}: expected array")
        return {}
    order_keys: list[bytes] = []
    result: dict[str, str] = {}
    for index, item in enumerate(value):
        item_label = f"{label}[{index}]"
        _exact_keys(item, SUBJECT_BINDING_FIELDS, item_label, errors)
        if not isinstance(item, Mapping):
            continue
        key = item.get("key")
        value_text = item.get("value")
        if not isinstance(key, str) or SUBJECT_BINDING_KEY_RE.fullmatch(key) is None:
            errors.append(f"{item_label}.key: invalid subject binding key")
        if not isinstance(value_text, str) or not value_text:
            errors.append(f"{item_label}.value: expected non-empty string")
        try:
            order_keys.append(canonical_json_bytes([key, value_text]))
        except (CanonicalizationError, TypeError, ValueError) as exc:
            errors.append(f"{item_label}: cannot canonicalize [key,value]: {exc}")
        if isinstance(key, str):
            if key in result:
                errors.append(f"{item_label}.key: duplicate subject binding key {key!r}")
            elif isinstance(value_text, str) and value_text:
                result[key] = value_text
    if order_keys != sorted(order_keys):
        errors.append(f"{label}: entries are not sorted by canonical [key,value] bytes")
    if len(order_keys) != len(set(order_keys)):
        errors.append(f"{label}: duplicate canonical [key,value] entry")
    return result


def _correlation_field_resolves_once(
    correlation: Mapping[str, Any],
    subject_bindings: Mapping[str, str],
    field: str,
) -> bool:
    resolutions = 0
    fixed_name = CORRELATION_EXPECTATION_FIXED_FIELDS.get(field)
    if fixed_name is not None and fixed_name in correlation:
        resolutions += 1
    if field in subject_bindings:
        resolutions += 1
    return resolutions == 1


def _load_case_record(root: Path, case_id: str, errors: list[str]) -> Mapping[str, Any] | None:
    direct = root / "acceptance" / "cases" / f"{case_id}.json"
    candidates: list[Path] = [direct]
    if not direct.exists() and case_id:
        candidates.append(root / "acceptance" / "cases" / f"registry-{case_id[0]}.json")
    for path in candidates:
        if not path.exists():
            continue
        try:
            document = _load_json_bytes(path.read_bytes(), f"Case registry {case_id}", errors)
        except OSError as exc:
            errors.append(f"Case registry {case_id}: cannot read {path}: {exc}")
            return None
        if not isinstance(document, Mapping):
            return None
        if document.get("id") == case_id:
            return document
        records = document.get("records")
        if isinstance(records, list):
            matches = [
                item for item in records if isinstance(item, Mapping) and item.get("id") == case_id
            ]
            if len(matches) == 1:
                return matches[0]
    errors.append(f"Case registry: no exact record for {case_id}")
    return None


def _validate_case_execution_contract(
    case_record: Mapping[str, Any],
    scenario: Mapping[str, Any],
    label: str,
    errors: list[str],
) -> None:
    """Reject a passing run whose independently derived Case is not executable."""

    case_id = case_record.get("caseId")
    classification = case_record.get("classification")
    if not isinstance(classification, Mapping):
        errors.append(f"{label}: Case {case_id} classification is missing")
        return
    if classification.get("scope") != "PRODUCT":
        errors.append(f"{label}: only a PRODUCT Case may close product status")
    case_status = classification.get("status")
    if case_status != "EXECUTABLE":
        errors.append(
            f"{label}: Case {case_id} status {case_status!r} is not product-closure eligible"
        )
    proof_boundary = classification.get("proofBoundaryOrNull")
    if isinstance(proof_boundary, str) and any(
        token in proof_boundary
        for token in ("COMPONENT_ONLY", "NOT_PRODUCT_CLOSURE", "REFERENCE_ONLY")
    ):
        errors.append(
            f"{label}: Case {case_id} proofBoundary remains {proof_boundary!r}"
        )
    boundary = case_record.get("evidenceBoundary")
    expected_boundary = {
        "productClosureGrade": "E3-END-TO-END-PRODUCT",
        "qualificationClosureGrade": "E4-PHYSICAL-QUALIFICATION",
        "componentOrReferenceEvidenceMayCloseProduct": False,
        "vmwareObservationMayCloseProduct": False,
        "blockedCaseMayExecuteAsClosure": False,
        "dependencyClosureRequired": True,
    }
    if boundary != expected_boundary:
        errors.append(f"{label}: Case {case_id} evidence boundary is not closed")


def _validate_case_scenario_binding(
    scenario: Mapping[str, Any],
    case_record: Mapping[str, Any],
    trace_values: Mapping[str, list[str]],
    status: Any,
    errors: list[str],
) -> None:
    """Bind a scenario to every immutable Case predicate and trace requirement."""

    case_id = case_record.get("caseId")
    if scenario.get("caseContractDigest") != case_record.get("caseContractDigest"):
        errors.append(
            "scenario.caseContractDigest: must equal the independently derived "
            f"Case {case_id} digest"
        )
    assertions = case_record.get("assertions")
    if not isinstance(assertions, list) or not assertions:
        errors.append(f"Case contract {case_id}.assertions: expected non-empty array")
        assertions = []
    bindings = scenario.get("casePredicateBindings")
    if not isinstance(bindings, list):
        errors.append("scenario.casePredicateBindings: expected array")
        bindings = []
    expected_assertions = {
        assertion.get("assertionId"): assertion
        for assertion in assertions
        if isinstance(assertion, Mapping)
        and isinstance(assertion.get("assertionId"), str)
    }
    actual_ids: list[Any] = []
    for index, binding in enumerate(bindings):
        binding_label = f"scenario.casePredicateBindings[{index}]"
        _exact_keys(binding, CASE_PREDICATE_BINDING_FIELDS, binding_label, errors)
        if not isinstance(binding, Mapping):
            continue
        assertion_id = binding.get("assertionId")
        actual_ids.append(assertion_id)
        assertion = expected_assertions.get(assertion_id)
        if not isinstance(assertion, Mapping):
            errors.append(f"{binding_label}.assertionId: unknown Case assertion")
            continue
        exact_fields = {
            "assertionDigest": "assertionDigest",
            "oracleClass": "requiredOracleClass",
            "predicateEvaluator": "predicateEvaluator",
        }
        for binding_field, assertion_field in exact_fields.items():
            if binding.get(binding_field) != assertion.get(assertion_field):
                errors.append(
                    f"{binding_label}.{binding_field}: must equal immutable Case "
                    f"assertion {assertion_field}"
                )
        symbol = binding.get("targetPredicateSymbolOrNull")
        interface_hash = binding.get("targetPredicateInterfaceHashOrNull")
        if status == "TEMPLATE":
            if symbol is not None or interface_hash is not None:
                errors.append(
                    f"{binding_label}: TEMPLATE target predicate binding must be null"
                )
        else:
            _nonempty_string(symbol, f"{binding_label}.targetPredicateSymbolOrNull", errors)
            _is_digest(
                interface_hash,
                f"{binding_label}.targetPredicateInterfaceHashOrNull",
                errors,
                nonzero=True,
            )
    expected_ids = [
        assertion.get("assertionId")
        for assertion in assertions
        if isinstance(assertion, Mapping)
    ]
    if actual_ids != expected_ids or len(actual_ids) != len(set(actual_ids)):
        errors.append(
            "scenario.casePredicateBindings: IDs/order must exactly equal all Case "
            f"assertions {expected_ids}"
        )



def _validate_fsm_state_map(
    value: Any,
    states: Mapping[str, set[str]],
    label: str,
    errors: list[str],
) -> None:
    if not isinstance(value, Mapping) or not value:
        errors.append(f"{label}: expected non-empty FSM state object")
        return
    for machine, state in value.items():
        if machine not in states:
            errors.append(f"{label}: unknown FSM {machine!r}")
        elif state not in states[machine]:
            errors.append(f"{label}.{machine}: unknown state {state!r}")


def _expected_oracle_ids(scenario: Mapping[str, Any]) -> dict[str, list[str]]:
    steps = scenario.get("steps", [])
    expected = scenario.get("expected", {})
    cleanup = scenario.get("cleanup", {})
    return {
        "immediateResults": [
            f"STEP-{item.get('sequence'):03d}-IMMEDIATE"
            for item in steps
            if isinstance(item, Mapping) and isinstance(item.get("sequence"), int)
        ],
        "finalStates": [f"FINAL-STATE:{machine}" for machine in expected.get("finalStates", {})],
        "mustOccur": [
            f"MUST-OCCUR:{index:03d}" for index, _ in enumerate(expected.get("mustOccur", []), 1)
        ],
        "mustNotOccur": [
            f"MUST-NOT-OCCUR:{index:03d}" for index, _ in enumerate(expected.get("mustNotOccur", []), 1)
        ],
        "authoritativeWrites": [
            f"AUTHORITATIVE-WRITE:{index:03d}"
            for index, _ in enumerate(expected.get("authoritativeWrites", []), 1)
        ],
        "physicalOracle": [
            f"PHYSICAL:{index:03d}" for index, _ in enumerate(expected.get("physicalOracle", []), 1)
        ],
        "idempotencyOracle": ["IDEMPOTENCY"],
        "cleanup": [
            *(f"CLEANUP-STATE:{machine}" for machine in cleanup.get("expectedStates", {})),
            *(
                f"CLEANUP-PROOF:{index:03d}"
                for index, _ in enumerate(cleanup.get("proofRequired", []), 1)
            ),
        ],
    }


def _validate_clean_release_receipt(
    document: Any,
    contract: Mapping[str, Any],
    trust: _TrustContext | None,
    label: str,
    errors: list[str],
    *,
    correlation: Mapping[str, Any] | None = None,
    subject_bindings: Mapping[str, str] | None = None,
    iteration_finished: _datetime.datetime | None = None,
) -> None:
    entity = _contract_indexes(contract)["entity_records"].get("ENTITY-CLEAN-RELEASE-RECEIPT")
    required = set(entity.get("requiredFields", [])) | set(entity.get("key", [])) if isinstance(entity, Mapping) else set()
    if not required:
        errors.append(f"{label}: portable clean-release entity definition is missing")
        return
    _exact_keys(document, required, label, errors)
    if not isinstance(document, Mapping):
        return
    if document.get("schemaVersion") != 1:
        errors.append(f"{label}.schemaVersion: expected 1")
    for field in (
        "receiptId",
        "sourceHostId",
        "assignmentId",
        "runId",
        "signerKeyId",
    ):
        _nonempty_string(document.get(field), f"{label}.{field}", errors)
    _base64url_decode(document.get("receiptNonce"), 16, f"{label}.receiptNonce", errors)
    relocation_id = document.get("relocationIdOrNull")
    relocation_generation = document.get("relocationGenerationOrNull")
    if (relocation_id is None) != (relocation_generation is None):
        errors.append(f"{label}: relocationIdOrNull and relocationGenerationOrNull must be null together")
    if relocation_id is not None:
        _nonempty_string(relocation_id, f"{label}.relocationIdOrNull", errors)
    for field in ("sourceHostEpoch", "oldRunGeneration"):
        _positive_safe_integer(document.get(field), f"{label}.{field}", errors)
    if relocation_generation is not None:
        _positive_safe_integer(
            relocation_generation,
            f"{label}.relocationGenerationOrNull",
            errors,
        )
    _positive_safe_integer(document.get("keyRingVersion"), f"{label}.keyRingVersion", errors)
    for field in (
        "leaseSetHash",
        "bindingsHash",
        "qemuExitProof",
        "dmaIrqTeardownProof",
        "iommuInvalidateProof",
        "resetStateProof",
        "ownerRestoreProof",
        "policyHash",
        "profileHash",
        "evidenceHash",
    ):
        _is_digest(document.get(field), f"{label}.{field}", errors, nonzero=True)
    for field in ("bundleIds", "bundleMembers"):
        _unique_strings(document.get(field), f"{label}.{field}", errors)
        _require_canonical_set_order(document.get(field), f"{label}.{field}", errors)
    for digest in document.get("bundleIds", []) if isinstance(document.get("bundleIds"), list) else []:
        _is_digest(digest, f"{label}.bundleIds", errors, nonzero=True)
    lease_bindings = document.get("leaseBindings")
    if not isinstance(lease_bindings, list) or not lease_bindings:
        errors.append(f"{label}.leaseBindings: expected non-empty array")
        lease_bindings = []
    canonical_keys: list[bytes] = []
    union_bundle_ids: set[str] = set()
    union_members: set[str] = set()
    lease_required = set(entity.get("leaseBindingRequiredFields", [])) if isinstance(entity, Mapping) else set()
    for index, lease in enumerate(lease_bindings):
        lease_label = f"{label}.leaseBindings[{index}]"
        _exact_keys(lease, lease_required, lease_label, errors)
        if not isinstance(lease, Mapping):
            continue
        _nonempty_string(lease.get("leaseId"), f"{lease_label}.leaseId", errors)
        _unique_strings(lease.get("memberDeviceUids"), f"{lease_label}.memberDeviceUids", errors)
        _require_canonical_set_order(lease.get("memberDeviceUids"), f"{lease_label}.memberDeviceUids", errors)
        _is_digest(lease.get("bundleId"), f"{lease_label}.bundleId", errors, nonzero=True)
        if isinstance(lease.get("bundleId"), str):
            union_bundle_ids.add(lease["bundleId"])
        if isinstance(lease.get("memberDeviceUids"), list):
            union_members.update(lease["memberDeviceUids"])
        _positive_safe_integer(
            lease.get("leaseVersion"), f"{lease_label}.leaseVersion", errors
        )
        old_generations = lease.get("oldDeviceGenerations")
        if not isinstance(old_generations, Mapping) or set(old_generations) != set(
            lease.get("memberDeviceUids", [])
        ):
            errors.append(f"{lease_label}.oldDeviceGenerations: keys must equal memberDeviceUids")
        else:
            for member_id, generation in old_generations.items():
                _nonempty_string(
                    member_id,
                    f"{lease_label}.oldDeviceGenerations key",
                    errors,
                )
                _positive_safe_integer(
                    generation,
                    f"{lease_label}.oldDeviceGenerations[{member_id!r}]",
                    errors,
                )
        try:
            canonical_keys.append(canonical_json_bytes([lease.get("bundleId"), lease.get("leaseId")]))
        except (CanonicalizationError, TypeError, ValueError) as exc:
            errors.append(f"{lease_label}: invalid order key: {exc}")
    if canonical_keys != sorted(canonical_keys) or len(canonical_keys) != len(set(canonical_keys)):
        errors.append(f"{label}.leaseBindings: must be unique and ordered by [bundleId,leaseId]")
    lease_set_digest = _canonical_digest(lease_bindings, f"{label}.leaseSetHash projection", errors)
    if lease_set_digest is not None and document.get("leaseSetHash") != lease_set_digest:
        errors.append(
            f"{label}.leaseSetHash: declared {document.get('leaseSetHash')}, actual {lease_set_digest}"
        )
    if set(document.get("bundleIds", [])) != union_bundle_ids:
        errors.append(f"{label}.bundleIds: must equal exact leaseBindings union")
    if set(document.get("bundleMembers", [])) != union_members:
        errors.append(f"{label}.bundleMembers: must equal exact leaseBindings union")
    new_generations = document.get("newDeviceGenerations")
    if not isinstance(new_generations, Mapping) or set(new_generations) != union_members:
        errors.append(f"{label}.newDeviceGenerations: keys must equal exact bundleMembers")
    else:
        for member_id, generation in new_generations.items():
            _nonempty_string(
                member_id, f"{label}.newDeviceGenerations key", errors
            )
            _positive_safe_integer(
                generation,
                f"{label}.newDeviceGenerations[{member_id!r}]",
                errors,
            )
    issued = _parse_time(document.get("issuedAt"), f"{label}.issuedAt", errors)
    expires = _parse_time(document.get("expiresAt"), f"{label}.expiresAt", errors)
    if issued is not None and expires is not None and issued >= expires:
        errors.append(f"{label}: issuedAt must precede expiresAt")
    if iteration_finished is not None and issued is not None and expires is not None:
        if issued > iteration_finished:
            errors.append(f"{label}.issuedAt: clean receipt postdates the completed run")
        if iteration_finished >= expires:
            errors.append(f"{label}.expiresAt: receipt was expired when the run completed")
    if correlation is not None:
        correlation_bindings = {
            "assignmentIdOrNull": "assignmentId",
            "runIdOrNull": "runId",
        }
        for correlation_field, receipt_field in correlation_bindings.items():
            value = correlation.get(correlation_field)
            if value is None or value != document.get(receipt_field):
                errors.append(
                    f"{label}: correlation.{correlation_field} must exactly equal "
                    f"receipt.{receipt_field}"
                )
    if subject_bindings is not None:
        exact_subjects = {
            "receiptId": document.get("receiptId"),
            "sourceHostId": document.get("sourceHostId"),
            "sourceHostEpoch": str(document.get("sourceHostEpoch")),
            "oldRunGeneration": str(document.get("oldRunGeneration")),
            "leaseSetHash": document.get("leaseSetHash"),
            "bindingsHash": document.get("bindingsHash"),
            "profileHash": document.get("profileHash"),
            "receiptDigest": document.get("receiptDigest"),
        }
        for field, expected in exact_subjects.items():
            if subject_bindings.get(field) != expected:
                errors.append(
                    f"{label}: correlation.subjectBindings[{field!r}] must equal "
                    f"the signed receipt value {expected!r}"
                )
        lease_id = subject_bindings.get("leaseId")
        receipt_lease_ids = {
            lease.get("leaseId")
            for lease in lease_bindings
            if isinstance(lease, Mapping)
        }
        if lease_id is None or lease_id not in receipt_lease_ids:
            errors.append(
                f"{label}: correlation.subjectBindings['leaseId'] must resolve one "
                "signed lease binding"
            )
    _verify_signed_envelope(
        document,
        digest_field="receiptDigest",
        signature_field="signature",
        signer_field="signerKeyId",
        signed_time_field="issuedAt",
        domain="QMAN-DIRECTPATH/CLEAN-RELEASE-RECEIPT/V1",
        required_role="HOST_RELEASE_EVIDENCE",
        trust=trust,
        label=label,
        errors=errors,
    )


def _validate_clean_release_acceptance(
    document: Any,
    receipt: Mapping[str, Any],
    trust: _TrustContext | None,
    label: str,
    errors: list[str],
    *,
    correlation: Mapping[str, Any] | None = None,
    subject_bindings: Mapping[str, str] | None = None,
    iteration_finished: _datetime.datetime | None = None,
) -> None:
    """Validate the repository-side, atomic acceptance of one release receipt.

    The host receipt proves physical teardown.  It does not itself prove that
    the global authority revoked the old lease set and advanced the assignment
    or relocation authority.  This independently signed record is that second
    half of the proof and must bind the receipt byte-for-byte through its digest
    and complete old-lease projection.
    """

    _exact_keys(document, CLEAN_RELEASE_ACCEPTANCE_FIELDS, label, errors)
    if not isinstance(document, Mapping):
        return

    def authority_id(field: str) -> str | None:
        value = _nonempty_string(
            document.get(field), f"{label}.{field}", errors, max_length=512
        )
        if value is not None and (value[0].isspace() or value[-1].isspace()):
            errors.append(f"{label}.{field}: leading/trailing whitespace is forbidden")
            return None
        return value

    for field in (
        "acceptanceId",
        "receiptId",
        "assignmentId",
        "runId",
        "sourceHostId",
        "repositoryTransactionId",
        "idempotencyKey",
        "repositorySignerKeyId",
    ):
        authority_id(field)

    kind = document.get("acceptanceKind")
    if kind not in {
        "ASSIGNMENT_CLEAN_RELEASE",
        "RELOCATION_SOURCE_CLEAN_RELEASE",
        "RELOCATION_TARGET_CLEAN_RELEASE",
    }:
        errors.append(f"{label}.acceptanceKind: unknown closed acceptance kind")
    relocation_id = document.get("relocationIdOrNull")
    relocation_generation = document.get("relocationGenerationOrNull")
    if relocation_id is not None:
        value = _nonempty_string(
            relocation_id,
            f"{label}.relocationIdOrNull",
            errors,
            max_length=512,
        )
        if value is not None and (value[0].isspace() or value[-1].isspace()):
            errors.append(
                f"{label}.relocationIdOrNull: leading/trailing whitespace is forbidden"
            )
    if relocation_generation is not None:
        _positive_safe_integer(
            relocation_generation,
            f"{label}.relocationGenerationOrNull",
            errors,
        )

    receipt_relocation = receipt.get("relocationIdOrNull")
    receipt_relocation_generation = receipt.get("relocationGenerationOrNull")
    if relocation_id != receipt_relocation:
        errors.append(f"{label}.relocationIdOrNull: does not match signed receipt")
    if relocation_generation != receipt_relocation_generation:
        errors.append(
            f"{label}.relocationGenerationOrNull: does not match signed receipt"
        )
    if receipt_relocation is None:
        if kind != "ASSIGNMENT_CLEAN_RELEASE":
            errors.append(
                f"{label}.acceptanceKind: assignment receipt requires "
                "ASSIGNMENT_CLEAN_RELEASE"
            )
        expected_authority_entity = "ENTITY-ASSIGNMENT-RUN"
    else:
        if kind not in {
            "RELOCATION_SOURCE_CLEAN_RELEASE",
            "RELOCATION_TARGET_CLEAN_RELEASE",
        }:
            errors.append(
                f"{label}.acceptanceKind: relocation receipt requires a relocation kind"
            )
        expected_authority_entity = "ENTITY-RELOCATION-RUN"
    if document.get("expectedAuthorityEntityId") != expected_authority_entity:
        errors.append(
            f"{label}.expectedAuthorityEntityId: expected {expected_authority_entity!r}"
        )

    receipt_bindings = receipt.get("leaseBindings")
    expected_binding_projection: list[dict[str, Any]] = []
    if isinstance(receipt_bindings, list):
        expected_binding_projection = [
            {
                field: copy.deepcopy(binding.get(field))
                for field in (
                    "leaseId",
                    "leaseVersion",
                    "bundleId",
                    "memberDeviceUids",
                )
            }
            for binding in receipt_bindings
            if isinstance(binding, Mapping)
        ]
        try:
            expected_binding_projection.sort(
                key=lambda binding: canonical_json_bytes(
                    [
                        binding.get("leaseId"),
                        binding.get("leaseVersion"),
                        binding.get("bundleId"),
                    ]
                )
            )
        except (CanonicalizationError, TypeError, ValueError) as exc:
            errors.append(f"{label}: cannot derive receipt lease projection: {exc}")

    bindings = document.get("expectedLeaseBindings")
    if not isinstance(bindings, list) or not bindings:
        errors.append(f"{label}.expectedLeaseBindings: expected non-empty array")
        bindings = []
    order_keys: list[bytes] = []
    for index, binding in enumerate(bindings):
        binding_label = f"{label}.expectedLeaseBindings[{index}]"
        _exact_keys(
            binding,
            CLEAN_RELEASE_ACCEPTANCE_LEASE_FIELDS,
            binding_label,
            errors,
        )
        if not isinstance(binding, Mapping):
            continue
        for field in ("leaseId",):
            _nonempty_string(binding.get(field), f"{binding_label}.{field}", errors)
        _positive_safe_integer(
            binding.get("leaseVersion"), f"{binding_label}.leaseVersion", errors
        )
        _is_digest(
            binding.get("bundleId"),
            f"{binding_label}.bundleId",
            errors,
            nonzero=True,
        )
        _unique_strings(
            binding.get("memberDeviceUids"),
            f"{binding_label}.memberDeviceUids",
            errors,
        )
        _require_canonical_set_order(
            binding.get("memberDeviceUids"),
            f"{binding_label}.memberDeviceUids",
            errors,
        )
        try:
            order_keys.append(
                canonical_json_bytes(
                    [
                        binding.get("leaseId"),
                        binding.get("leaseVersion"),
                        binding.get("bundleId"),
                    ]
                )
            )
        except (CanonicalizationError, TypeError, ValueError) as exc:
            errors.append(f"{binding_label}: invalid canonical order key: {exc}")
    if order_keys != sorted(order_keys) or len(order_keys) != len(set(order_keys)):
        errors.append(
            f"{label}.expectedLeaseBindings: must be unique and canonically ordered"
        )
    if bindings != expected_binding_projection:
        errors.append(
            f"{label}.expectedLeaseBindings: must exactly equal the signed receipt's "
            "complete old lease projection"
        )

    receipt_matches = {
        "receiptId": "receiptId",
        "receiptDigest": "receiptDigest",
        "assignmentId": "assignmentId",
        "runId": "runId",
        "oldRunGeneration": "oldRunGeneration",
        "sourceHostId": "sourceHostId",
        "expectedSourceHostEpoch": "sourceHostEpoch",
        "expectedLeaseSetHash": "leaseSetHash",
        "receiptExpiresAt": "expiresAt",
    }
    for acceptance_field, receipt_field in receipt_matches.items():
        if document.get(acceptance_field) != receipt.get(receipt_field):
            errors.append(
                f"{label}.{acceptance_field}: must equal signed "
                f"receipt.{receipt_field}"
            )
    for field in ("receiptDigest", "expectedLeaseSetHash"):
        _is_digest(document.get(field), f"{label}.{field}", errors, nonzero=True)

    positive_fields = (
        "oldRunGeneration",
        "expectedSourceHostEpoch",
        "expectedAuthorityResourceVersion",
        "committedAuthorityResourceVersion",
        "leaseRevocationCommitVersion",
        "controllerGeneration",
        "keyRingVersion",
    )
    positive_values = {
        field: _positive_safe_integer(document.get(field), f"{label}.{field}", errors)
        for field in positive_fields
    }
    expected_version = positive_values["expectedAuthorityResourceVersion"]
    committed_version = positive_values["committedAuthorityResourceVersion"]
    if (
        expected_version is not None
        and committed_version is not None
        and committed_version != expected_version + 1
    ):
        errors.append(
            f"{label}.committedAuthorityResourceVersion: must equal "
            "expectedAuthorityResourceVersion + 1"
        )

    accepted = _parse_time(document.get("acceptedAt"), f"{label}.acceptedAt", errors)
    receipt_expires = _parse_time(
        document.get("receiptExpiresAt"), f"{label}.receiptExpiresAt", errors
    )
    receipt_issued = _parse_time(
        receipt.get("issuedAt"), f"{label} bound receipt.issuedAt", errors
    )
    if accepted is not None and receipt_expires is not None and accepted > receipt_expires:
        errors.append(f"{label}.acceptedAt: signed receipt had already expired")
    if accepted is not None and receipt_issued is not None and accepted < receipt_issued:
        errors.append(f"{label}.acceptedAt: cannot precede receipt issuance")
    if iteration_finished is not None and accepted is not None and accepted > iteration_finished:
        errors.append(f"{label}.acceptedAt: repository acceptance postdates completed run")

    if correlation is not None:
        for correlation_field, acceptance_field in (
            ("assignmentIdOrNull", "assignmentId"),
            ("runIdOrNull", "runId"),
        ):
            if correlation.get(correlation_field) != document.get(acceptance_field):
                errors.append(
                    f"{label}: correlation.{correlation_field} must exactly equal "
                    f"acceptance.{acceptance_field}"
                )
    if subject_bindings is not None:
        exact_subjects = {
            "acceptanceId": document.get("acceptanceId"),
            "acceptanceDigest": document.get("acceptanceDigest"),
            "receiptId": document.get("receiptId"),
            "receiptDigest": document.get("receiptDigest"),
            "repositoryTransactionId": document.get("repositoryTransactionId"),
            "idempotencyKey": document.get("idempotencyKey"),
            "expectedLeaseSetHash": document.get("expectedLeaseSetHash"),
            "expectedAuthorityResourceVersion": str(
                document.get("expectedAuthorityResourceVersion")
            ),
            "committedAuthorityResourceVersion": str(
                document.get("committedAuthorityResourceVersion")
            ),
        }
        for field, expected in exact_subjects.items():
            if subject_bindings.get(field) != expected:
                errors.append(
                    f"{label}: correlation.subjectBindings[{field!r}] must equal "
                    f"the signed acceptance value {expected!r}"
                )

    _verify_signed_envelope(
        document,
        digest_field="acceptanceDigest",
        signature_field="signature",
        signer_field="repositorySignerKeyId",
        signed_time_field="acceptedAt",
        domain="QMAN-DIRECTPATH/CLEAN-RELEASE-ACCEPTANCE/V1",
        required_role="CONTROL_REPOSITORY_EVIDENCE",
        trust=trust,
        label=label,
        errors=errors,
    )


def _scenario_map_binding_digest(mapping: Mapping[str, Any], errors: list[str]) -> str | None:
    return _canonical_digest(
        _scenario_binding_projection(mapping), "scenario integration-map binding projection", errors
    )


def _scenario_request_transition_edges(
    value: Any,
    step_operation_id: str | None,
    result: list[tuple[str, str, str | None, set[str]]],
) -> None:
    if isinstance(value, Mapping):
        source = value.get("fromState")
        if not isinstance(source, str):
            source = value.get("expectedState")
        target = value.get("toState")
        if isinstance(source, str) and isinstance(target, str):
            referenced_operations: set[str] = set()

            def collect(candidate: Any) -> None:
                if isinstance(candidate, str) and candidate.startswith("OP-"):
                    referenced_operations.add(candidate)
                elif isinstance(candidate, Mapping):
                    for child in candidate.values():
                        collect(child)
                elif isinstance(candidate, list):
                    for child in candidate:
                        collect(child)

            collect(value)
            if isinstance(step_operation_id, str):
                referenced_operations.add(step_operation_id)
            result.append((source, target, step_operation_id, referenced_operations))
        for child in value.values():
            _scenario_request_transition_edges(child, step_operation_id, result)
    elif isinstance(value, list):
        for child in value:
            _scenario_request_transition_edges(child, step_operation_id, result)


def _validate_typed_scenario_traceability(
    scenario: Mapping[str, Any],
    contract: Mapping[str, Any],
    indexes: Mapping[str, Any],
    trace_values: Mapping[str, list[str]],
    request_payloads: Sequence[Any] | None,
    errors: list[str],
) -> None:
    trace_label = "scenario.traceability"
    steps = scenario.get("steps", [])
    operation_ids = {
        step.get("operationId")
        for step in steps
        if isinstance(step, Mapping) and isinstance(step.get("operationId"), str)
    }
    operation_records = indexes.get("operation_records", {})
    port_ids = {
        operation_records[operation_id].get("ownerPortId")
        for operation_id in operation_ids
        if operation_id in operation_records
        and isinstance(operation_records[operation_id].get("ownerPortId"), str)
    }
    preconditions = scenario.get("preconditions", {})
    expected = scenario.get("expected", {})
    cleanup = scenario.get("cleanup", {})
    initial_states = (
        preconditions.get("initialStates", {})
        if isinstance(preconditions, Mapping)
        else {}
    )
    final_states = (
        expected.get("finalStates", {}) if isinstance(expected, Mapping) else {}
    )
    cleanup_states = (
        cleanup.get("expectedStates", {}) if isinstance(cleanup, Mapping) else {}
    )
    state_machine_ids = {
        *initial_states.keys(),
        *final_states.keys(),
        *cleanup_states.keys(),
    }
    authoritative_writes = (
        expected.get("authoritativeWrites", []) if isinstance(expected, Mapping) else []
    )
    entity_ids = {
        write.get("entityId")
        for write in authoritative_writes
        if isinstance(write, Mapping)
        and isinstance(write.get("entityId"), str)
    }
    for machine_id in state_machine_ids:
        machine = indexes.get("machines", {}).get(machine_id)
        if isinstance(machine, Mapping) and isinstance(machine.get("entityId"), str):
            entity_ids.add(machine["entityId"])
    case_id = scenario.get("caseId")
    eligible_test_ids = {
        test_id
        for test_id, record in indexes.get("tests", {}).items()
        if isinstance(record, Mapping) and case_id in record.get("caseIds", [])
    }
    test_ids = set(trace_values.get("testObligationIds", []))
    if not test_ids or not test_ids.issubset(eligible_test_ids):
        errors.append(
            f"{trace_label}.testObligationIds: expected a non-empty subset of Case "
            f"obligations {sorted(eligible_test_ids)}"
        )
    parity_ids = {
        parity_id
        for parity_id, record in indexes.get("parity", {}).items()
        if isinstance(record, Mapping)
        and set(record.get("testObligationIds", [])) & test_ids
        and set(record.get("implementationPortIds", [])) & port_ids
    }
    reason_ids = set(trace_values.get("expectedReasonCodes", []))
    exact_sets = {
        "operationIds": operation_ids,
        "portIds": port_ids,
        "entityIds": entity_ids,
        "stateMachineIds": state_machine_ids,
        "parityObligationIds": parity_ids,
    }
    for field, derived in exact_sets.items():
        declared = set(trace_values.get(field, []))
        if declared != derived:
            errors.append(
                f"{trace_label}.{field}: must equal independently derived "
                f"{sorted(derived)}"
            )

    edges: list[tuple[str, str, str | None, set[str]]] = []
    for step_number, step in enumerate(steps):
        if not isinstance(step, Mapping):
            continue
        operation_id = step.get("operationId")
        request_value = step.get("request")
        if request_payloads is not None and step_number < len(request_payloads):
            request_value = request_payloads[step_number]
        _scenario_request_transition_edges(
            request_value,
            operation_id if isinstance(operation_id, str) else None,
            edges,
        )
    derived_transition_ids: list[str] = []
    derived_transition_records: list[tuple[str, Mapping[str, Any]]] = []
    for edge_index, (source, target, step_operation, referenced_operations) in enumerate(edges):
        matches: list[tuple[str, str, Mapping[str, Any]]] = []
        for transition_id, indexed in indexes.get("transitions", {}).items():
            machine = indexed.get("machine") if isinstance(indexed, Mapping) else None
            transition = indexed.get("transition") if isinstance(indexed, Mapping) else None
            if not isinstance(machine, Mapping) or not isinstance(transition, Mapping):
                continue
            machine_id = machine.get("id")
            if machine_id not in state_machine_ids or transition.get("to") != target:
                continue
            portable_source = transition.get("from")
            source_expansion = transition.get("fromStateExpansion")
            source_matches = portable_source == source or (
                isinstance(source_expansion, list) and source in source_expansion
            )
            if not source_matches:
                continue
            transition_operations = set(transition.get("operationIds", []))
            if not (transition_operations & referenced_operations):
                continue
            matches.append((transition_id, machine_id, transition))
        if len(matches) != 1:
            errors.append(
                f"{trace_label}.transitionIds: request edge {edge_index + 1} "
                f"{source}->{target} under {step_operation!r} resolves to "
                f"{[item[0] for item in matches]}; expected exactly one"
            )
            continue
        transition_id, machine_id, transition = matches[0]
        derived_transition_ids.append(transition_id)
        derived_transition_records.append((machine_id, transition))
    declared_transition_ids = set(trace_values.get("transitionIds", []))
    if not edges and declared_transition_ids:
        # TEMPLATE scenarios deliberately have no detached payload bytes.  Rebuild
        # their path from the declared closed transition set plus independently
        # declared initial/final states and the exact step operation set.  This is
        # stronger than accepting the declaration as a narrative: every edge must
        # be uniquely reachable and every declared edge must be consumed.
        pending: dict[str, tuple[str, Mapping[str, Any]]] = {}
        for transition_id in declared_transition_ids:
            indexed = indexes.get("transitions", {}).get(transition_id)
            machine = indexed.get("machine") if isinstance(indexed, Mapping) else None
            transition = (
                indexed.get("transition") if isinstance(indexed, Mapping) else None
            )
            machine_id = machine.get("id") if isinstance(machine, Mapping) else None
            if not isinstance(machine_id, str) or not isinstance(transition, Mapping):
                errors.append(
                    f"{trace_label}.transitionIds: unknown closed transition "
                    f"{transition_id!r}"
                )
                continue
            if machine_id not in state_machine_ids:
                errors.append(
                    f"{trace_label}.transitionIds: {transition_id!r} belongs to "
                    "an undeclared state machine"
                )
            transition_operations = set(transition.get("operationIds", []))
            if not (transition_operations & operation_ids):
                errors.append(
                    f"{trace_label}.transitionIds: {transition_id!r} has no "
                    "operation exercised by this scenario"
                )
            pending[transition_id] = (machine_id, transition)
        fallback_states = dict(initial_states)
        while pending:
            reachable = [
                (transition_id, machine_id, transition)
                for transition_id, (machine_id, transition) in pending.items()
                if fallback_states.get(machine_id) == transition.get("from")
                or (
                    isinstance(transition.get("fromStateExpansion"), list)
                    and fallback_states.get(machine_id)
                    in transition.get("fromStateExpansion", [])
                )
            ]
            if not reachable:
                errors.append(
                    f"{trace_label}.transitionIds: declared transition set is not "
                    f"a contiguous path from initial states; pending={sorted(pending)}"
                )
                break
            by_machine: dict[str, list[tuple[str, Mapping[str, Any]]]] = {}
            for transition_id, machine_id, transition in reachable:
                by_machine.setdefault(machine_id, []).append(
                    (transition_id, transition)
                )
            ambiguous = {
                machine_id: sorted(item[0] for item in candidates)
                for machine_id, candidates in by_machine.items()
                if len(candidates) != 1
            }
            if ambiguous:
                errors.append(
                    f"{trace_label}.transitionIds: declared path branches "
                    f"ambiguously {ambiguous}"
                )
                break
            for machine_id in sorted(by_machine, key=canonical_json_bytes):
                transition_id, transition = by_machine[machine_id][0]
                derived_transition_ids.append(transition_id)
                derived_transition_records.append((machine_id, transition))
                fallback_states[machine_id] = transition.get("to")
                del pending[transition_id]
    if len(derived_transition_ids) != len(set(derived_transition_ids)):
        errors.append(f"{trace_label}.transitionIds: one transition is exercised twice ambiguously")
    if declared_transition_ids != set(derived_transition_ids):
        errors.append(
            f"{trace_label}.transitionIds: must equal exact executable path "
            f"{sorted(set(derived_transition_ids))}"
        )
    current_states = dict(initial_states)
    for machine_id, transition in derived_transition_records:
        current = current_states.get(machine_id)
        source = transition.get("from")
        expansion = transition.get("fromStateExpansion")
        if current != source and not (
            isinstance(expansion, list) and current in expansion
        ):
            errors.append(
                f"{trace_label}.transitionIds: non-contiguous {machine_id} path at "
                f"{transition.get('id')} from current {current!r}"
            )
        current_states[machine_id] = transition.get("to")
    for machine_id, expected_state in final_states.items():
        if current_states.get(machine_id) != expected_state:
            errors.append(
                f"{trace_label}.transitionIds: derived {machine_id} state "
                f"{current_states.get(machine_id)!r}, expected {expected_state!r}"
            )

    contract_item_ids = (
        operation_ids
        | port_ids
        | entity_ids
        | state_machine_ids
        | set(derived_transition_ids)
        | test_ids
        | parity_ids
        | reason_ids
        | set(trace_values.get("canonicalizationProfileIds", []))
        | set(trace_values.get("guardIds", []))
        | set(trace_values.get("configIds", []))
        | set(trace_values.get("migrationIds", []))
        | set(trace_values.get("telemetryIds", []))
    )
    if set(trace_values.get("contractItemIds", [])) != contract_item_ids:
        errors.append(
            f"{trace_label}.contractItemIds: must equal exact typed union "
            f"{sorted(contract_item_ids)}"
        )


def _validate_scenario_payload_binding(
    binding: Any,
    *,
    operation_id: Any,
    direction: str,
    definition_status: Any,
    evidence_git: _GitView | None,
    root: Path,
    label: str,
    errors: list[str],
) -> Mapping[str, Any] | None:
    """Resolve one scenario fixture through the frozen operation profile table."""

    if not isinstance(binding, Mapping):
        errors.append(f"{label}: expected typed operation payload binding")
        return None
    exact_values = {
        "operationId": operation_id,
        "direction": direction,
        "payloadSchemaAuthority": "PORTABLE_CONTRACT",
        "payloadCanonicalProfile": "CANONICAL-JSON-V1",
    }
    for field, expected in exact_values.items():
        if binding.get(field) != expected:
            errors.append(f"{label}.{field}: expected {expected!r}")

    schema_path = "contracts/directpath-operation-payload.schema.json"
    schema_blob = _worktree_bytes(root, schema_path, f"{label}.payloadSchema", errors)
    _check_blob_hash(
        schema_blob,
        binding.get("payloadSchemaSha256"),
        f"{label}.payloadSchema",
        errors,
    )
    schema_document = (
        _load_json_bytes(schema_blob, f"{label}.payloadSchema", errors)
        if schema_blob is not None
        else None
    )
    profile_rows = (
        schema_document.get("x-operationProfileIndex")
        if isinstance(schema_document, Mapping)
        else None
    )
    matches = [
        item
        for item in (profile_rows if isinstance(profile_rows, list) else [])
        if isinstance(item, Mapping) and item.get("operationId") == operation_id
    ]
    if len(matches) != 1:
        errors.append(
            f"{label}.operationId: expected one frozen payload profile row, "
            f"found {len(matches)}"
        )
        expected_ref = None
        expected_profile_id = None
    else:
        prefix = "request" if direction == "REQUEST" else "result"
        expected_ref = matches[0].get(f"{prefix}SchemaRef")
        expected_profile_id = matches[0].get(f"{prefix}ProfileId")
        if binding.get("payloadSchemaRef") != expected_ref:
            errors.append(
                f"{label}.payloadSchemaRef: expected frozen fragment {expected_ref!r}"
            )

    payload_path = binding.get("payloadPathOrNull")
    payload_hash = binding.get("payloadHashOrNull")
    if definition_status == "TEMPLATE":
        if payload_path is not None or payload_hash is not None:
            errors.append(f"{label}: TEMPLATE payload path/hash must both be null")
        return None
    if not isinstance(payload_path, str) or not isinstance(payload_hash, str):
        errors.append(f"{label}: BOUND/EXECUTED_PASS requires a payload path/hash")
        return None
    if evidence_git is None:
        errors.append(f"{label}: pinned evidence repository E is unavailable")
        return None
    payload_blob = evidence_git.blob(payload_path, f"{label}.payloadPathOrNull", errors)
    if payload_blob is None:
        return None
    payload = _load_json_bytes(payload_blob, f"{label}.payload", errors)
    if payload is None:
        return None
    if isinstance(expected_ref, str):
        _validate_closed_json_schema_instance(
            payload, root, expected_ref, f"{label}.payload", errors
        )
    if not isinstance(payload, Mapping):
        errors.append(f"{label}.payload: expected object")
        return None
    expected_payload = {
        "operationId": operation_id,
        "direction": direction,
        "profileId": expected_profile_id,
        "canonicalProfile": "CANONICAL-JSON-V1",
    }
    for field, expected in expected_payload.items():
        if payload.get(field) != expected:
            errors.append(f"{label}.payload.{field}: expected {expected!r}")
    canonical_payload_hash = _canonical_digest(
        payload, f"{label}.payloadHashOrNull projection", errors
    )
    if payload_hash != canonical_payload_hash:
        errors.append(
            f"{label}.payloadHashOrNull: canonical payload digest mismatch"
        )

    if direction == "RESULT":
        body = payload.get("body")
        if not isinstance(body, Mapping):
            errors.append(f"{label}.payload.body: expected result object")
            return payload
        outcome = body.get("outcome")
        failure = body.get("errorOrNull")
        reason = failure.get("reasonCode") if isinstance(failure, Mapping) else None
        retryable = failure.get("retryable") if isinstance(failure, Mapping) else False
        expected_projection = {
            "expectedStatus": outcome,
            "expectedReasonCodeOrNull": reason,
            "expectedRetryable": retryable,
        }
        for field, expected in expected_projection.items():
            if binding.get(field) != expected:
                errors.append(
                    f"{label}.{field}: expected exact RESULT payload projection "
                    f"{expected!r}"
                )
    return payload


def _scenario_core(
    scenario: Mapping[str, Any],
    contract: Mapping[str, Any],
    root: Path,
    errors: list[str],
    *,
    mapping: Mapping[str, Any] | None,
    code_git: _GitView | None,
    evidence_git: _GitView | None,
    trust: _TrustContext | None,
    risks: set[str],
) -> None:
    _exact_keys(scenario, SCENARIO_FIELDS, "scenario", errors)
    if scenario.get("schemaVersion") != 1:
        errors.append("scenario.schemaVersion: expected 1")
    if scenario.get("scope") != "PRODUCT":
        errors.append("scenario.scope: expected PRODUCT")
    if scenario.get("targetMilestone") not in {"G1", "G2", "G3", "G4", "G5", "G6"}:
        errors.append("scenario.targetMilestone: unknown milestone")
    status = scenario.get("definitionStatus")
    if status not in {"TEMPLATE", "BOUND", "EXECUTED_PASS"}:
        errors.append(f"scenario.definitionStatus: unknown status {status!r}")
    indexes = _contract_indexes(contract)
    case_id = scenario.get("caseId")
    if case_id not in indexes["cases"]:
        errors.append(f"scenario.caseId: unknown closed Case ID {case_id!r}")
    case_registry = _load_case_contract_registry(contract, root, errors)
    case_record = None
    if isinstance(case_registry, Mapping) and isinstance(case_id, str):
        matches = [
            item
            for item in case_registry.get("records", [])
            if isinstance(item, Mapping) and item.get("caseId") == case_id
        ]
        if len(matches) != 1:
            errors.append(
                f"Case contract registry: expected exactly one record for {case_id}, "
                f"found {len(matches)}"
            )
        else:
            case_record = matches[0]
    applicability = scenario.get("applicability")
    _exact_keys(applicability, APPLICABILITY_FIELDS, "scenario.applicability", errors)
    if isinstance(applicability, Mapping):
        for field in ("platformProfileIds", "backendFamilies", "deviceTraitFamilies"):
            _unique_strings(applicability.get(field), f"scenario.applicability.{field}", errors)
        if type(applicability.get("requiresPhysicalHardware")) is not bool:
            errors.append("scenario.applicability.requiresPhysicalHardware: expected boolean")
        backend_families = set(applicability.get("backendFamilies", [])) if isinstance(applicability.get("backendFamilies"), list) else set()
        policy_path = root / "contracts" / "compatibility-profile-policy.json"
        try:
            policy = _load_json_bytes(policy_path.read_bytes(), "compatibility profile policy", errors)
        except OSError as exc:
            errors.append(f"compatibility profile policy: cannot read: {exc}")
            policy = None
        if isinstance(policy, Mapping):
            backend_policy = policy.get("backendPolicy", {})
            known_backends = {
                backend_policy.get("currentProductFamily"),
                *backend_policy.get("futureFamilies", []),
            }
            unknown = sorted(backend_families - known_backends)
            if unknown:
                errors.append(f"scenario.applicability.backendFamilies: unknown families {unknown}")
    trace = scenario.get("traceability")
    _exact_keys(trace, TRACE_FIELDS, "scenario.traceability", errors)
    trace_values: dict[str, list[str]] = {}
    if isinstance(trace, Mapping):
        for field in TRACE_FIELDS:
            trace_values[field] = _unique_strings(
                trace.get(field),
                f"scenario.traceability.{field}",
                errors,
                nonempty=field
                not in {
                    "canonicalizationProfileIds",
                    "guardIds",
                    "configIds",
                    "migrationIds",
                    "telemetryIds",
                    "transitionIds",
                    "expectedReasonCodes",
                },
            )
            _require_canonical_set_order(
                trace.get(field), f"scenario.traceability.{field}", errors
            )
        try:
            known_contract_items = {
                item["contractItemId"] for item in derive_mapping_items(contract)
            }
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(
                "scenario.traceability.contractItemIds: cannot derive the closed "
                f"mapping surface: {exc}"
            )
            known_contract_items = set()
        registries = {
            "contractItemIds": known_contract_items,
            "canonicalizationProfileIds": {
                item.get("id")
                for item in contract.get("canonicalizationContract", {}).get("profiles", [])
                if isinstance(item, Mapping) and isinstance(item.get("id"), str)
            },
            "guardIds": {
                item.get("id")
                for item in contract.get("safetyGuards", [])
                if isinstance(item, Mapping) and isinstance(item.get("id"), str)
            },
            "configIds": {
                item.get("id")
                for item in contract.get("configurationContract", {}).get("settings", [])
                if isinstance(item, Mapping) and isinstance(item.get("id"), str)
            },
            "migrationIds": {
                item.get("id")
                for item in contract.get("migrationContract", {}).get("steps", [])
                if isinstance(item, Mapping) and isinstance(item.get("id"), str)
            },
            "telemetryIds": {
                item.get("id")
                for item in contract.get("telemetryContract", {}).get("metrics", [])
                if isinstance(item, Mapping) and isinstance(item.get("id"), str)
            },
            "techStoryIds": indexes["tech_stories"],
            "riskIds": risks,
            "portIds": indexes["ports"],
            "operationIds": indexes["operations"],
            "entityIds": indexes["entities"],
            "stateMachineIds": set(indexes["machines"]),
            "transitionIds": set(indexes["transitions"]),
            "testObligationIds": set(indexes["tests"]),
            "parityObligationIds": set(indexes["parity"]),
            "expectedReasonCodes": set(indexes["reasons"]),
        }
        for field, registry in registries.items():
            unknown = sorted(set(trace_values.get(field, [])) - registry)
            if unknown:
                errors.append(f"scenario.traceability.{field}: unknown closed IDs {unknown}")
    if isinstance(case_record, Mapping) and isinstance(trace, Mapping):
        classification = case_record.get("classification", {})
        case_risks = set(classification.get("riskIds", [])) if isinstance(classification, Mapping) else set()
        case_stories = set(classification.get("techStoryIds", [])) if isinstance(classification, Mapping) else set()
        if set(trace_values.get("riskIds", [])) != case_risks:
            errors.append(
                f"scenario.traceability.riskIds: must exactly equal Case {case_id} registry {sorted(case_risks)}"
            )
        if set(trace_values.get("techStoryIds", [])) != case_stories:
            errors.append(
                f"scenario.traceability.techStoryIds: must exactly equal Case {case_id} registry {sorted(case_stories)}"
            )
        if scenario.get("targetMilestone") != classification.get("targetMilestone"):
            errors.append(f"scenario.targetMilestone: does not match Case {case_id} registry")
        _validate_case_scenario_binding(
            scenario,
            case_record,
            trace_values,
            status,
            errors,
        )
    preconditions = scenario.get("preconditions")
    _exact_keys(preconditions, PRECONDITION_FIELDS, "scenario.preconditions", errors)
    fixtures: list[Any] = []
    if isinstance(preconditions, Mapping):
        _validate_fsm_state_map(
            preconditions.get("initialStates"), indexes["states"], "scenario.preconditions.initialStates", errors
        )
        authority = preconditions.get("authority")
        _exact_keys(authority, AUTHORITY_FIELDS, "scenario.preconditions.authority", errors)
        if isinstance(authority, Mapping):
            for field in AUTHORITY_FIELDS:
                value = authority.get(field)
                if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                    errors.append(f"scenario.preconditions.authority.{field}: expected nonnegative integer")
        if not isinstance(preconditions.get("fixtures"), list) or not preconditions.get("fixtures"):
            errors.append("scenario.preconditions.fixtures: expected non-empty array")
        else:
            fixtures = preconditions["fixtures"]
            _require_canonical_set_order(
                fixtures, "scenario.preconditions.fixtures", errors
            )
        for index, fixture in enumerate(fixtures):
            label = f"scenario.preconditions.fixtures[{index}]"
            _exact_keys(fixture, FIXTURE_FIELDS, label, errors)
            if isinstance(fixture, Mapping):
                _is_digest(
                    fixture.get("digest"),
                    f"{label}.digest",
                    errors,
                    nonzero=status in {"BOUND", "EXECUTED_PASS"},
                )
        _unique_strings(preconditions.get("facts"), "scenario.preconditions.facts", errors)
    steps = scenario.get("steps")
    if not isinstance(steps, list) or not steps:
        errors.append("scenario.steps: expected non-empty array")
        steps = []
    step_operations: list[str] = []
    resolved_request_payloads: list[Any] = []
    fault_points: set[str] = set()
    fault_classes_by_point: dict[str, list[str]] = {}
    for index, step in enumerate(steps):
        label = f"scenario.steps[{index}]"
        _exact_keys(step, STEP_FIELDS, label, errors, optional={"faultInjection"})
        if not isinstance(step, Mapping):
            continue
        if step.get("sequence") != index + 1:
            errors.append(f"{label}.sequence: expected {index + 1}")
        operation = step.get("operationId")
        if operation not in indexes["operations"]:
            errors.append(f"{label}.operationId: unknown operation {operation!r}")
        elif isinstance(operation, str):
            step_operations.append(operation)
        request_payload = _validate_scenario_payload_binding(
            step.get("request"),
            operation_id=operation,
            direction="REQUEST",
            definition_status=status,
            evidence_git=evidence_git,
            root=root,
            label=f"{label}.request",
            errors=errors,
        )
        result_payload = _validate_scenario_payload_binding(
            step.get("expectedImmediateResult"),
            operation_id=operation,
            direction="RESULT",
            definition_status=status,
            evidence_git=evidence_git,
            root=root,
            label=f"{label}.expectedImmediateResult",
            errors=errors,
        )
        resolved_request_payloads.append(request_payload)
        if status in {"BOUND", "EXECUTED_PASS"}:
            request_binding = step.get("request")
            result_binding = step.get("expectedImmediateResult")
            if isinstance(request_binding, Mapping) and isinstance(
                result_binding, Mapping
            ):
                for role_field in ("payloadPathOrNull", "payloadHashOrNull"):
                    if request_binding.get(role_field) == result_binding.get(role_field):
                        errors.append(
                            f"{label}: REQUEST and RESULT must use distinct "
                            f"{role_field} identities"
                        )
        del request_payload, result_payload
        fault = step.get("faultInjection")
        if fault is not None:
            _exact_keys(fault, FAULT_FIELDS, f"{label}.faultInjection", errors)
            if isinstance(fault, Mapping):
                point = fault.get("point")
                declared_classes = _unique_strings(
                    fault.get("faultClasses"),
                    f"{label}.faultInjection.faultClasses",
                    errors,
                )
                _require_canonical_set_order(
                    fault.get("faultClasses"),
                    f"{label}.faultInjection.faultClasses",
                    errors,
                )
                if not isinstance(point, str) or not point:
                    errors.append(f"{label}.faultInjection.point: expected non-empty string")
                else:
                    if point in fault_points:
                        errors.append(
                            f"{label}.faultInjection.point: duplicate declared point {point!r}"
                        )
                    fault_points.add(point)
                    fault_classes_by_point[point] = declared_classes
    if isinstance(trace, Mapping) and set(trace_values.get("operationIds", [])) != set(step_operations):
        errors.append("scenario.traceability.operationIds: must equal the exact step operation set")
    expected = scenario.get("expected")
    _exact_keys(expected, EXPECTED_FIELDS, "scenario.expected", errors)
    if isinstance(expected, Mapping):
        _validate_fsm_state_map(
            expected.get("finalStates"), indexes["states"], "scenario.expected.finalStates", errors
        )
        for field in ("mustOccur", "mustNotOccur", "physicalOracle"):
            _unique_strings(expected.get(field), f"scenario.expected.{field}", errors)
        writes = expected.get("authoritativeWrites")
        if not isinstance(writes, list) or not writes:
            errors.append("scenario.expected.authoritativeWrites: expected non-empty array")
            writes = []
        for index, write in enumerate(writes):
            label = f"scenario.expected.authoritativeWrites[{index}]"
            _exact_keys(write, WRITE_FIELDS, label, errors)
            if isinstance(write, Mapping) and write.get("entityId") not in indexes["entities"]:
                errors.append(f"{label}.entityId: unknown Entity ID {write.get('entityId')!r}")
        reason_code = expected.get("reasonCode")
        if reason_code is not None:
            reason = indexes["reasons"].get(reason_code)
            if reason is None:
                errors.append(f"scenario.expected.reasonCode: unknown Reason {reason_code!r}")
            else:
                if expected.get("retryable") is not reason.get("retryable"):
                    errors.append(
                        f"scenario.expected.retryable: must equal closed Reason registry value {reason.get('retryable')}"
                    )
            if reason_code not in trace_values.get("expectedReasonCodes", []):
                errors.append("scenario.expected.reasonCode: missing from trace expectedReasonCodes")
        elif expected.get("retryable") is not False:
            errors.append("scenario.expected.retryable: a null reason cannot be retryable")
    artifacts = scenario.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("scenario.artifacts: expected non-empty array")
        artifacts = []
    for index, artifact in enumerate(artifacts):
        label = f"scenario.artifacts[{index}]"
        _exact_keys(artifact, ARTIFACT_EXPECTATION_FIELDS, label, errors)
        if isinstance(artifact, Mapping):
            if artifact.get("hashRequired") is not True:
                errors.append(f"{label}.hashRequired: must be true")
            _validate_correlation_expectation_fields(
                artifact.get("correlationFields"),
                f"{label}.correlationFields",
                errors,
            )
    artifact_formats = [
        artifact.get("formatOrSchema")
        for artifact in artifacts
        if isinstance(artifact, Mapping)
    ]
    clean_release_required = (
        "OP-PROVE-CLEAN-RELEASE" in step_operations
        or "ENTITY-CLEAN-RELEASE-RECEIPT" in artifact_formats
        or "ENTITY-CLEAN-RELEASE-ACCEPTANCE" in artifact_formats
    )
    if clean_release_required:
        required_artifact_correlations = {
            "ENTITY-CLEAN-RELEASE-RECEIPT": {
                "leaseId",
                "oldRunGeneration",
                "profileHash",
                "receiptDigest",
                "receiptId",
                "runId",
                "sourceHostEpoch",
                "sourceHostId",
                "bindingsHash",
                "leaseSetHash",
            },
            "ENTITY-CLEAN-RELEASE-ACCEPTANCE": {
                "acceptanceDigest",
                "acceptanceId",
                "assignmentId",
                "committedAuthorityResourceVersion",
                "expectedAuthorityResourceVersion",
                "expectedLeaseSetHash",
                "idempotencyKey",
                "receiptDigest",
                "receiptId",
                "repositoryTransactionId",
                "runId",
            },
        }
        for expected_format, required_fields in required_artifact_correlations.items():
            matching_expectations = [
                artifact
                for artifact in artifacts
                if isinstance(artifact, Mapping)
                and artifact.get("formatOrSchema") == expected_format
            ]
            if len(matching_expectations) != 1:
                errors.append(
                    f"scenario.artifacts: clean release requires exactly one "
                    f"{expected_format} expectation"
                )
                continue
            declared_fields = set(
                matching_expectations[0].get("correlationFields", [])
            )
            missing_fields = required_fields - declared_fields
            if missing_fields:
                errors.append(
                    f"scenario.artifacts {expected_format}: missing signed subject "
                    f"correlations {sorted(missing_fields)}"
                )
        expected_writes = (
            expected.get("authoritativeWrites", [])
            if isinstance(expected, Mapping)
            else []
        )
        written_entities = {
            write.get("entityId")
            for write in expected_writes
            if isinstance(write, Mapping)
        }
        required_writes = {
            "ENTITY-CLEAN-RELEASE-RECEIPT",
            "ENTITY-CLEAN-RELEASE-ACCEPTANCE",
        }
        missing_writes = required_writes - written_entities
        if missing_writes:
            errors.append(
                "scenario.expected.authoritativeWrites: clean release must expose "
                f"both physical receipt and repository acceptance {sorted(missing_writes)}"
            )
    cleanup = scenario.get("cleanup")
    _exact_keys(cleanup, CLEANUP_FIELDS, "scenario.cleanup", errors)
    if isinstance(cleanup, Mapping):
        if cleanup.get("required") is not True:
            errors.append("scenario.cleanup.required: must be true")
        _validate_fsm_state_map(
            cleanup.get("expectedStates"), indexes["states"], "scenario.cleanup.expectedStates", errors
        )
        _unique_strings(cleanup.get("proofRequired"), "scenario.cleanup.proofRequired", errors)
    if status == "EXECUTED_PASS" and isinstance(case_record, Mapping):
        _validate_case_execution_contract(
            case_record,
            scenario,
            "scenario Case execution contract",
            errors,
        )
    if isinstance(trace, Mapping):
        _validate_typed_scenario_traceability(
            scenario,
            contract,
            indexes,
            trace_values,
            resolved_request_payloads,
            errors,
        )
    execution = scenario.get("execution")
    _exact_keys(execution, EXECUTION_FIELDS, "scenario.execution", errors)
    repeat = None
    fault_plan_counts: dict[str | None, int] = {}
    if isinstance(execution, Mapping):
        if execution.get("targetTestBindingRequired") is not True:
            errors.append("scenario.execution.targetTestBindingRequired: must be true")
        repeat = execution.get("repeat")
        if not isinstance(repeat, int) or isinstance(repeat, bool) or repeat < 1:
            errors.append("scenario.execution.repeat: expected positive integer")
            repeat = None
        fault_plan = execution.get("faultPointPlan")
        if not isinstance(fault_plan, list) or not fault_plan:
            errors.append("scenario.execution.faultPointPlan: expected non-empty array")
            fault_plan = []
        _require_canonical_set_order(
            fault_plan, "scenario.execution.faultPointPlan", errors
        )
        for index, plan_item in enumerate(fault_plan):
            plan_label = f"scenario.execution.faultPointPlan[{index}]"
            _exact_keys(plan_item, FAULT_POINT_PLAN_FIELDS, plan_label, errors)
            if not isinstance(plan_item, Mapping):
                continue
            point = plan_item.get("faultPointOrNull")
            plan_classes = _unique_strings(
                plan_item.get("faultClasses"),
                f"{plan_label}.faultClasses",
                errors,
            )
            _require_canonical_set_order(
                plan_item.get("faultClasses"),
                f"{plan_label}.faultClasses",
                errors,
            )
            if point is not None and (not isinstance(point, str) or not point):
                errors.append(f"{plan_label}.faultPointOrNull: expected null or non-empty string")
                continue
            count = plan_item.get("repeat")
            if not isinstance(count, int) or isinstance(count, bool) or count < 1:
                errors.append(f"{plan_label}.repeat: expected positive integer")
                continue
            if point in fault_plan_counts:
                errors.append(f"{plan_label}.faultPointOrNull: duplicate plan point {point!r}")
            else:
                fault_plan_counts[point] = count
            expected_classes = (
                fault_classes_by_point.get(point, []) if point is not None else []
            )
            if plan_classes != expected_classes:
                errors.append(
                    f"{plan_label}.faultClasses: must exactly equal step fault "
                    f"classes {expected_classes}"
                )
        expected_plan_points: set[str | None] = set(fault_points) if fault_points else {None}
        if set(fault_plan_counts) != expected_plan_points:
            errors.append(
                "scenario.execution.faultPointPlan: points must exactly equal declared "
                f"step injections {sorted(fault_points)!r}; use one null entry only when none are declared"
            )
        if repeat is not None and sum(fault_plan_counts.values()) != repeat:
            errors.append(
                "scenario.execution.faultPointPlan: repeat sum must exactly equal "
                f"execution.repeat {repeat}"
            )
        if isinstance(case_record, Mapping):
            required_faults = set(case_record.get("requiredFaultClasses", []))
            declared_faults = {
                fault_class
                for values in fault_classes_by_point.values()
                for fault_class in values
            }
            if declared_faults != required_faults:
                errors.append(
                    "scenario fault classes: declared union must exactly equal Case "
                    f"contract {sorted(required_faults)}"
                )
            minimum_repeat = case_record.get("minimumRepeat")
            if (
                isinstance(repeat, int)
                and isinstance(minimum_repeat, int)
                and repeat < minimum_repeat
            ):
                errors.append(
                    "scenario.execution.repeat: below Case minimumRepeat "
                    f"{minimum_repeat}"
                )
    target = scenario.get("targetBinding")
    result = scenario.get("executionResult")
    if status == "TEMPLATE":
        if target is not None or result is not None:
            errors.append("scenario TEMPLATE: targetBinding and executionResult must be null")
        return
    if target is None:
        errors.append(f"scenario {status}: targetBinding is required")
        return
    _exact_keys(target, SCENARIO_TARGET_FIELDS, "scenario.targetBinding", errors)
    if not isinstance(target, Mapping):
        return
    if mapping is None:
        errors.append("scenario.targetBinding: exact integration map is required")
    if target.get("hashScope") != "GIT_BLOB_BYTES":
        errors.append("scenario.targetBinding.hashScope: only GIT_BLOB_BYTES is authoritative")
    target_commit = _normal_commit(
        target.get("repositoryCommit"), "scenario.targetBinding.repositoryCommit", errors
    )
    target_object_format = target.get("repositoryObjectFormat")
    if target_object_format not in {"SHA1", "SHA256"}:
        errors.append(
            "scenario.targetBinding.repositoryObjectFormat: expected SHA1 or SHA256"
        )
    elif target_commit is not None:
        expected_length = 40 if target_object_format == "SHA1" else 64
        if len(target_commit) != expected_length:
            errors.append(
                "scenario.targetBinding.repositoryCommit: length does not match "
                f"{target_object_format}"
            )
    if code_git is not None and target_commit != code_git.commit:
        errors.append("scenario.targetBinding.repositoryCommit: does not match pinned integration map")
    if target.get("artifactGraphPosition") != "EVIDENCE_BLOB_EMBEDS_C_AND_M_NOT_E":
        errors.append(
            "scenario.targetBinding.artifactGraphPosition: expected "
            "EVIDENCE_BLOB_EMBEDS_C_AND_M_NOT_E"
        )
    contract_digest = _canonical_digest(contract, "portable contract", errors)
    if contract_digest is not None and target.get("portableContractSha256") != contract_digest:
        errors.append("scenario.targetBinding.portableContractSha256: does not bind this contract")
    if mapping is not None:
        if target.get("integrationMapId") != mapping.get("mapId"):
            errors.append("scenario.targetBinding.integrationMapId: does not match integration map")
        if target.get("mappingCoreId") != mapping.get("mappingCoreId"):
            errors.append("scenario.targetBinding.mappingCoreId: does not match detached M")
        binding_digest = _scenario_map_binding_digest(mapping, errors)
        if binding_digest is not None and target.get("integrationMapSha256") != binding_digest:
            errors.append(
                "scenario.targetBinding.integrationMapSha256: does not equal scenarioBindingDigest projection"
            )
        repository = mapping.get("targetRepository")
        if isinstance(repository, Mapping):
            if target.get("repositoryId") != repository.get("repositoryId"):
                errors.append("scenario.targetBinding.repositoryId: does not match integration map")
            if target.get("repositoryObjectFormat") != repository.get("objectFormat"):
                errors.append(
                    "scenario.targetBinding.repositoryObjectFormat: does not match integration map C"
                )
    for field in (
        "testInterfaceHash",
        "fixtureSetHash",
        "platformProfileDigest",
        "backendProfileDigest",
        "trustKeyRingSha256",
    ):
        _is_digest(target.get(field), f"scenario.targetBinding.{field}", errors, nonzero=True)
    qualification_correlation_fields = (
        "qualificationRunIdOrNull",
        "qualificationRunRequestDigestOrNull",
        "qualificationRunRequestNonceDigestOrNull",
    )
    target_grade = target.get("evidenceGrade")
    if target_grade == "E3-END-TO-END-PRODUCT":
        if any(target.get(field) is not None for field in qualification_correlation_fields):
            errors.append(
                "scenario.targetBinding: E3 requires null qualification-run correlation"
            )
    elif target_grade == "E4-PHYSICAL-QUALIFICATION":
        if not isinstance(target.get("qualificationRunIdOrNull"), str) or not target.get(
            "qualificationRunIdOrNull"
        ):
            errors.append(
                "scenario.targetBinding.qualificationRunIdOrNull: E4 requires an identifier"
            )
        for field in qualification_correlation_fields[1:]:
            _is_digest(
                target.get(field),
                f"scenario.targetBinding.{field}",
                errors,
                nonzero=True,
            )
    else:
        errors.append("scenario.targetBinding.evidenceGrade: unsupported grade")
    fixture_set_digest = _canonical_digest(
        fixtures, "scenario.preconditions fixture-set projection", errors
    )
    if fixture_set_digest is not None and target.get("fixtureSetHash") != fixture_set_digest:
        errors.append(
            "scenario.targetBinding.fixtureSetHash: does not equal the exact canonical "
            "precondition fixture set"
        )
    test_blob = (
        code_git.blob(
            target.get("testPath"), "scenario.targetBinding.testPath", errors
        )
        if code_git
        else None
    )
    _check_blob_hash(test_blob, target.get("testInterfaceHash"), "scenario.targetBinding.test", errors)
    trusted_test_symbol = False
    if mapping is not None:
        for map_item in mapping.get("mappings", []):
            if not isinstance(map_item, Mapping):
                continue
            for symbol_binding in map_item.get("targetBindings", []):
                if not isinstance(symbol_binding, Mapping):
                    continue
                if (
                    symbol_binding.get("path") == target.get("testPath")
                    and symbol_binding.get("symbol") == target.get("testSymbol")
                    and symbol_binding.get("interfaceHash") == target.get("testInterfaceHash")
                    and symbol_binding.get("symbolKind") in {"TEST", "FUNCTION"}
                ):
                    trusted_test_symbol = True
    if not trusted_test_symbol:
        errors.append(
            "scenario.targetBinding.testSymbol: no signed target symbol-index binding proves this test declaration"
        )
    ring_blob = (
        evidence_git.blob(
            target.get("trustKeyRingPath"),
            "scenario.targetBinding.trustKeyRingPath",
            errors,
        )
        if evidence_git
        else None
    )
    _check_blob_hash(
        ring_blob, target.get("trustKeyRingSha256"), "scenario.targetBinding.trustKeyRing", errors
    )
    if status == "BOUND":
        if result is not None:
            errors.append("scenario BOUND: executionResult must be null")
        return
    if result is None:
        errors.append("scenario EXECUTED_PASS: executionResult is required")
        return
    _validate_execution_result(
        scenario,
        result,
        contract,
        evidence_git,
        trust,
        repeat,
        fault_plan_counts,
        {None: [], **fault_classes_by_point},
        artifacts,
        errors,
        root=root,
        code_git=code_git,
        mapping=mapping,
        case_registry=case_registry,
        case_record=case_record,
    )


def _validate_iteration_oracle_matrix(
    matrix: Any,
    expected_ids: Mapping[str, list[str]],
    allowed_artifact_hashes: set[str],
    label: str,
    errors: list[str],
) -> set[str]:
    """Validate one iteration's complete oracle matrix and local evidence."""

    _exact_keys(matrix, ORACLE_CATEGORY_FIELDS, label, errors)
    if not isinstance(matrix, Mapping):
        return set()
    all_ids: list[str] = []
    cleanup_evidence: set[str] = set()
    for category in ORACLE_CATEGORY_FIELDS:
        records = matrix.get(category)
        category_label = f"{label}.{category}"
        if not isinstance(records, list):
            errors.append(f"{category_label}: expected array")
            continue
        actual_ids: list[str] = []
        for index, oracle in enumerate(records):
            oracle_label = f"{category_label}[{index}]"
            _exact_keys(oracle, ORACLE_FIELDS, oracle_label, errors)
            if not isinstance(oracle, Mapping):
                continue
            oracle_id = oracle.get("oracleId")
            actual_ids.append(oracle_id)
            all_ids.append(oracle_id)
            if oracle.get("verdict") != "PASS":
                errors.append(f"{oracle_label}.verdict: expected PASS")
            if not isinstance(oracle.get("observed"), str) or not oracle.get("observed"):
                errors.append(f"{oracle_label}.observed: expected non-empty observation")
            evidence = _unique_strings(
                oracle.get("evidenceArtifactHashes"),
                f"{oracle_label}.evidenceArtifactHashes",
                errors,
            )
            _require_canonical_set_order(
                oracle.get("evidenceArtifactHashes"),
                f"{oracle_label}.evidenceArtifactHashes",
                errors,
            )
            for digest in evidence:
                _is_digest(
                    digest,
                    f"{oracle_label}.evidenceArtifactHashes",
                    errors,
                    nonzero=True,
                )
                if digest not in allowed_artifact_hashes:
                    errors.append(
                        f"{oracle_label}: evidence {digest!r} is not correlated "
                        "to this exact iteration"
                    )
            if category == "cleanup":
                cleanup_evidence.update(evidence)
        if actual_ids != expected_ids.get(category, []):
            errors.append(
                f"{category_label}: exact IDs/order must be "
                f"{expected_ids.get(category, [])}"
            )
    if len(all_ids) != len(set(all_ids)):
        errors.append(f"{label}: duplicate oracleId across categories")
    return cleanup_evidence


def _target_symbol_matches(
    mapping: Mapping[str, Any] | None,
    *,
    symbol: Any,
    interface_hash: Any,
    path: Any | None = None,
) -> list[Mapping[str, Any]]:
    if not isinstance(mapping, Mapping):
        return []
    matches: list[Mapping[str, Any]] = []
    for entry in mapping.get("mappings", []):
        if not isinstance(entry, Mapping):
            continue
        for binding in entry.get("targetBindings", []):
            if not isinstance(binding, Mapping):
                continue
            if binding.get("symbol") != symbol or binding.get("interfaceHash") != interface_hash:
                continue
            if path is not None and binding.get("path") != path:
                continue
            if binding.get("symbolKind") not in {"FUNCTION", "TEST"}:
                continue
            matches.append(binding)
    return matches


def _git_repository_tree_v1(
    git: _GitView | None, label: str, errors: list[str]
) -> str | None:
    """Hash every regular blob at C using the portable REPOSITORY_TREE_V1 frame."""

    if git is None or not git.ready:
        errors.append(f"{label}: pinned target repository is unavailable")
        return None
    listing = git._run(["ls-tree", "-r", "-z", git.commit])
    if listing is None:
        errors.append(f"{label}: cannot enumerate target Git tree")
        return None
    records: list[tuple[bytes, dict[str, str]]] = []
    folded_paths: dict[str, str] = {}
    for index, raw_entry in enumerate(listing.rstrip(b"\x00").split(b"\x00")):
        if not raw_entry:
            continue
        try:
            metadata, raw_path = raw_entry.split(b"\t", 1)
            mode, object_type, object_id = metadata.split(b" ", 2)
            path = raw_path.decode("utf-8", errors="strict")
        except (ValueError, UnicodeDecodeError) as exc:
            errors.append(f"{label}: cannot parse Git tree entry {index}: {exc}")
            continue
        if mode not in {b"100644", b"100755"} or object_type != b"blob":
            errors.append(
                f"{label}: symlink/submodule/non-regular entry is forbidden: {path!r}"
            )
            continue
        try:
            _validate_unicode(path, f"{label} path")
        except CanonicalizationError as exc:
            errors.append(str(exc))
            continue
        collision_key = unicodedata.normalize("NFC", path).casefold()
        if collision_key in folded_paths and folded_paths[collision_key] != path:
            errors.append(
                f"{label}: NFC/case-fold path collision "
                f"{folded_paths[collision_key]!r} vs {path!r}"
            )
        folded_paths[collision_key] = path
        blob = git._run(["cat-file", "blob", object_id.decode("ascii")])
        if blob is None:
            errors.append(f"{label}: cannot read Git blob for {path!r}")
            continue
        record = {"path": path, "sha256": sha256(blob)}
        records.append((canonical_json_bytes(path), record))
    return _canonical_digest(
        [record for _, record in sorted(records, key=lambda item: item[0])],
        f"{label} projection",
        errors,
    )


def _git_tracked_tree_entries(
    git: _GitView | None, label: str, errors: list[str]
) -> list[dict[str, Any]] | None:
    """Reconstruct GIT-TRACKED-TREE-CLOSURE-V1 entries from the object database."""

    if git is None or not git.ready:
        errors.append(f"{label}: pinned target Git repository is unavailable")
        return None
    head = git._run(["rev-parse", "HEAD"])
    if head is None or head.decode("ascii", errors="replace").strip().lower() != git.commit:
        errors.append(f"{label}: checked-out HEAD must equal target commit C")
    status = git._run(["status", "--porcelain=v1", "--untracked-files=all"])
    if status is None:
        errors.append(f"{label}: cannot prove clean target worktree")
    elif status:
        errors.append(
            f"{label}: dirty or untracked build inputs are forbidden "
            f"({len(status.splitlines())} status entries)"
        )
    listing = git._run(["ls-tree", "-r", "-z", git.commit])
    if listing is None:
        errors.append(f"{label}: cannot enumerate target Git tree")
        return None
    expected_object_length = len(git.commit or "")
    entries: list[tuple[bytes, dict[str, Any]]] = []
    normalized_paths: set[str] = set()
    for number, raw_entry in enumerate(listing.rstrip(b"\x00").split(b"\x00")):
        if not raw_entry:
            continue
        try:
            metadata, raw_path = raw_entry.split(b"\t", 1)
            mode_bytes, object_type, object_id_bytes = metadata.split(b" ", 2)
            path = raw_path.decode("utf-8", errors="strict")
            mode = mode_bytes.decode("ascii")
            object_id = object_id_bytes.decode("ascii")
        except (ValueError, UnicodeDecodeError) as exc:
            errors.append(f"{label}: cannot parse Git tree entry {number}: {exc}")
            continue
        if unicodedata.normalize("NFC", path) != path:
            errors.append(f"{label}: non-NFC Git path {path!r}")
        if path in normalized_paths:
            errors.append(f"{label}: duplicate normalized Git path {path!r}")
        normalized_paths.add(path)
        if (
            re.fullmatch(r"[0-9a-f]+", object_id) is None
            or len(object_id) != expected_object_length
        ):
            errors.append(f"{label}: invalid Git object ID for {path!r}")
        if mode in {"100644", "100755", "120000"} and object_type == b"blob":
            content = git._run(["cat-file", "blob", object_id])
            if content is None:
                errors.append(f"{label}: cannot read tracked blob {path!r}")
                continue
        elif mode == "160000" and object_type == b"commit":
            content = object_id.encode("ascii")
        else:
            errors.append(
                f"{label}: unsupported mode/type {mode!r}/{object_type!r} for {path!r}"
            )
            continue
        record = {
            "path": path,
            "mode": mode,
            "gitObjectId": object_id,
            "contentSha256": sha256(content),
            "byteLength": len(content),
        }
        entries.append((raw_path, record))
    return [record for _, record in sorted(entries, key=lambda item: item[0])]


def _validate_source_tree_manifest(
    build: Mapping[str, Any],
    code_git: _GitView | None,
    evidence_git: _GitView | None,
    root: Path,
    label: str,
    errors: list[str],
    *,
    _seen: set[tuple[str, str]] | None = None,
    _depth: int = 0,
    _budget: list[int] | None = None,
    _tracked_paths: set[str] | None = None,
    _tracked_entries: dict[str, Mapping[str, Any]] | None = None,
    _path_prefix: str = "",
) -> Mapping[str, Any] | None:
    if _depth > 16:
        errors.append(f"{label}: recursive source-tree depth exceeds 16")
        return None
    budget = _budget if _budget is not None else [256]
    tracked_paths = _tracked_paths if _tracked_paths is not None else set()
    tracked_entries = _tracked_entries if _tracked_entries is not None else {}
    schema_ref = "contracts/directpath-source-tree-manifest.schema.json"
    schema_blob = _worktree_bytes(root, schema_ref, f"{label}.schema", errors)
    _check_blob_hash(
        schema_blob,
        build.get("sourceTreeManifestSchemaSha256"),
        f"{label}.schema",
        errors,
    )
    manifest_blob = (
        evidence_git.blob(
            build.get("sourceTreeManifestPath"),
            f"{label}.sourceTreeManifestPath",
            errors,
        )
        if evidence_git is not None
        else None
    )
    _check_blob_hash(
        manifest_blob,
        build.get("sourceTreeManifestSha256"),
        f"{label}.sourceTreeManifest",
        errors,
    )
    manifest = (
        _load_json_bytes(manifest_blob, f"{label}.sourceTreeManifest", errors)
        if manifest_blob is not None
        else None
    )
    if not isinstance(manifest, Mapping):
        return None
    _validate_closed_json_schema_instance(
        manifest,
        root,
        schema_ref,
        f"{label}.sourceTreeManifest",
        errors,
    )
    projection = copy.deepcopy(dict(manifest))
    projection["sourceTreeSha256"] = None
    actual_digest = _canonical_digest(
        projection, f"{label}.sourceTreeManifest projection", errors
    )
    if manifest.get("sourceTreeSha256") != actual_digest:
        errors.append(f"{label}.sourceTreeManifest.sourceTreeSha256: digest mismatch")
    if build.get("sourceTreeSha256") != actual_digest:
        errors.append(f"{label}.sourceTreeSha256: internal manifest digest mismatch")
    expected_commit = code_git.commit if code_git is not None else None
    if _normal_commit(
        manifest.get("targetRepositoryCommit"),
        f"{label}.sourceTreeManifest.targetRepositoryCommit",
        errors,
    ) != expected_commit:
        errors.append(f"{label}.sourceTreeManifest: target commit C mismatch")
    expected_format = "SHA1" if isinstance(expected_commit, str) and len(expected_commit) == 40 else "SHA256"
    if manifest.get("repositoryObjectFormat") != expected_format:
        errors.append(f"{label}.sourceTreeManifest.repositoryObjectFormat: mismatch")
    if manifest.get("algorithm") != "GIT-TRACKED-TREE-CLOSURE-V1" or manifest.get(
        "rootPath"
    ) != ".":
        errors.append(f"{label}.sourceTreeManifest: unsupported algorithm/rootPath")
    expected_entries = _git_tracked_tree_entries(code_git, label, errors)
    if expected_entries is not None and manifest.get("entries") != expected_entries:
        errors.append(
            f"{label}.sourceTreeManifest.entries: not the complete exact tracked tree at C"
        )
    for entry in expected_entries or []:
        entry_path = entry.get("path") if isinstance(entry, Mapping) else None
        if (
            isinstance(entry_path, str)
            and isinstance(entry, Mapping)
            and entry.get("mode") != "160000"
        ):
            complete_path = f"{_path_prefix}{entry_path}"
            tracked_paths.add(complete_path)
            tracked_entries[complete_path] = entry
    gitlinks = {
        item.get("path"): item
        for item in (expected_entries or [])
        if isinstance(item, Mapping) and item.get("mode") == "160000"
    }
    submodules = manifest.get("submoduleTrees")
    if not isinstance(submodules, list):
        submodules = []
    submodule_paths: list[str] = []
    for number, item in enumerate(submodules):
        if not isinstance(item, Mapping):
            continue
        path_value = item.get("path")
        if not isinstance(path_value, str):
            errors.append(
                f"{label}.sourceTreeManifest.submoduleTrees[{number}].path: "
                "expected string"
            )
            continue
        submodule_paths.append(path_value)
    if submodule_paths != sorted(
        submodule_paths,
        key=lambda value: value.encode("utf-8") if isinstance(value, str) else b"",
    ) or len(submodule_paths) != len(set(submodule_paths)):
        errors.append(f"{label}.sourceTreeManifest.submoduleTrees: invalid path order")
    if set(submodule_paths) != set(gitlinks):
        errors.append(
            f"{label}.sourceTreeManifest.submoduleTrees: must bijectively cover gitlinks"
        )
    seen = _seen if _seen is not None else set()
    if code_git is not None and code_git.path is not None and code_git.commit is not None:
        current_identity = (str(code_git.path), code_git.commit)
        if current_identity in seen:
            errors.append(f"{label}: recursive submodule cycle")
            return manifest
        seen = {*seen, current_identity}
    for number, submodule in enumerate(submodules):
        sub_label = f"{label}.sourceTreeManifest.submoduleTrees[{number}]"
        if not isinstance(submodule, Mapping):
            continue
        if budget[0] <= 0:
            errors.append(f"{label}: recursive source-tree count exceeds 256")
            break
        budget[0] -= 1
        path = submodule.get("path")
        gitlink = gitlinks.get(path) if isinstance(path, str) else None
        if not isinstance(gitlink, Mapping) or submodule.get("commit") != gitlink.get(
            "gitObjectId"
        ):
            errors.append(f"{sub_label}.commit: gitlink mismatch")
            continue
        if code_git is None or code_git.path is None or not isinstance(path, str):
            errors.append(f"{sub_label}: local submodule checkout is unavailable")
            continue
        submodule_path = code_git.path.joinpath(*PurePosixPath(path).parts)
        commit = submodule.get("commit")
        object_format = "SHA1" if isinstance(commit, str) and len(commit) == 40 else "SHA256"
        sub_git = _GitView(
            root,
            {
                "repositoryLocation": str(submodule_path),
                "objectFormat": object_format,
                "commit": commit,
            },
            errors,
            f"{sub_label}.repository",
        )
        nested_build = {
            "sourceTreeManifestPath": submodule.get("manifestPath"),
            "sourceTreeManifestSha256": submodule.get("manifestSha256"),
            "sourceTreeManifestSchemaSha256": build.get(
                "sourceTreeManifestSchemaSha256"
            ),
            "sourceTreeSha256": submodule.get("sourceTreeSha256"),
        }
        _validate_source_tree_manifest(
            nested_build,
            sub_git,
            evidence_git,
            root,
            sub_label,
            errors,
            _seen=seen,
            _depth=_depth + 1,
            _budget=budget,
            _tracked_paths=tracked_paths,
            _tracked_entries=tracked_entries,
            _path_prefix=f"{_path_prefix}{path}/",
        )
    return manifest


BUILD_ATTESTATION_DESCRIPTOR_FIELDS = {
    "path",
    "sha256",
    "byteLength",
    "mediaType",
    "schemaRef",
    "schemaSha256",
    "attestationDigest",
}


def _validate_build_artifact(
    descriptor: Any,
    evidence_git: _GitView | None,
    label: str,
    errors: list[str],
) -> bytes | None:
    """Resolve one closed BuildAttestation artifact descriptor at E."""

    if not isinstance(descriptor, Mapping):
        errors.append(f"{label}: expected artifact descriptor")
        return None
    blob = (
        evidence_git.blob(descriptor.get("path"), f"{label}.path", errors)
        if evidence_git is not None
        else None
    )
    if evidence_git is None:
        errors.append(f"{label}: pinned evidence repository E is unavailable")
    _check_blob_hash(blob, descriptor.get("sha256"), label, errors)
    if blob is not None and descriptor.get("byteLength") != len(blob):
        errors.append(
            f"{label}.byteLength: declared {descriptor.get('byteLength')!r}, "
            f"actual {len(blob)}"
        )
    if blob is not None and descriptor.get("mediaType") == "application/json":
        _load_json_bytes(blob, f"{label} JSON", errors)
    return blob


def _validate_identifier_order(
    records: Any,
    identifier_field: str,
    label: str,
    errors: list[str],
) -> dict[str, Mapping[str, Any]]:
    """Require unique NFC identifiers sorted by their exact UTF-8 bytes."""

    if not isinstance(records, list):
        errors.append(f"{label}: expected array")
        return {}
    identifiers: list[str] = []
    result: dict[str, Mapping[str, Any]] = {}
    for number, record in enumerate(records):
        if not isinstance(record, Mapping):
            errors.append(f"{label}[{number}]: expected object")
            continue
        identifier = record.get(identifier_field)
        if not isinstance(identifier, str) or not identifier:
            errors.append(
                f"{label}[{number}].{identifier_field}: expected non-empty string"
            )
            continue
        try:
            _validate_unicode(identifier, f"{label}[{number}].{identifier_field}")
        except CanonicalizationError as exc:
            errors.append(str(exc))
            continue
        identifiers.append(identifier)
        if identifier in result:
            errors.append(f"{label}: duplicate {identifier_field} {identifier!r}")
        else:
            result[identifier] = record
    if identifiers != sorted(identifiers, key=lambda item: item.encode("utf-8")):
        errors.append(f"{label}: records are not sorted by {identifier_field} UTF-8 bytes")
    return result


def _domain_projection_digest(
    domain: str,
    projection: Any,
    label: str,
    errors: list[str],
) -> str | None:
    try:
        return sha256(domain.encode("ascii") + b"\x00" + canonical_json_bytes(projection))
    except (CanonicalizationError, UnicodeEncodeError, TypeError, ValueError) as exc:
        errors.append(f"{label}: cannot canonicalize domain projection: {exc}")
        return None


def _trust_key_at_history_version(
    trust: _TrustContext | None,
    key_ring_version: Any,
    key_id: Any,
    evidence_git: _GitView | None,
    root: Path,
    label: str,
    errors: list[str],
) -> tuple[Mapping[str, Any] | None, Mapping[str, Any] | None]:
    """Resolve one signer through the authenticated, rollback-safe ring history."""

    if trust is None:
        errors.append(f"{label}: authenticated trust context is unavailable")
        return None, None
    current_sequence = trust.key_ring.get("keyRingSequence")
    ring: Mapping[str, Any] | None = None
    if key_ring_version == current_sequence:
        ring = trust.key_ring
    else:
        history = trust.key_ring_history
        descriptors = history.get("rings") if isinstance(history, Mapping) else None
        matches = [
            item
            for item in (descriptors if isinstance(descriptors, list) else [])
            if isinstance(item, Mapping)
            and item.get("keyRingSequence") == key_ring_version
        ]
        if len(matches) != 1:
            errors.append(
                f"{label}.keyRingVersion: expected one authenticated history ring, "
                f"found {len(matches)}"
            )
            return None, None
        ring_blob = _typed_artifact_from_git(
            matches[0],
            evidence_git,
            root,
            f"{label}.keyRingHistory",
            errors,
            expected_schema_ref="contracts/directpath-trust-key-ring.schema.json",
            descriptor_fields=TRUST_KEY_RING_HISTORY_DESCRIPTOR_FIELDS,
        )
        parsed = (
            _load_json_bytes(ring_blob, f"{label}.keyRingHistory", errors)
            if ring_blob is not None
            else None
        )
        if isinstance(parsed, Mapping):
            _validate_rooted_key_ring(
                parsed,
                trust.root_set,
                f"{label}.keyRingHistory",
                errors,
            )
            ring = parsed
    if not isinstance(ring, Mapping):
        return None, None
    keys = {
        item.get("keyId"): item
        for item in ring.get("keys", [])
        if isinstance(item, Mapping) and isinstance(item.get("keyId"), str)
    }
    key = keys.get(key_id) if isinstance(key_id, str) else None
    if key is None:
        errors.append(f"{label}.executorKeyId: unknown key {key_id!r}")
        return ring, None
    revoked = ring.get("revokedKeyIds")
    current_revoked = trust.key_ring.get("revokedKeyIds")
    if (
        isinstance(revoked, list)
        and key_id in revoked
        or isinstance(current_revoked, list)
        and key_id in current_revoked
    ):
        errors.append(f"{label}.executorKeyId: key is revoked")
    return ring, key


def _verify_history_signed_envelope(
    document: Mapping[str, Any],
    *,
    digest_field: str,
    signature_field: str,
    signer_field: str,
    signed_time_field: str,
    domain: str,
    required_role: str,
    trust: _TrustContext | None,
    evidence_git: _GitView | None,
    root: Path,
    label: str,
    errors: list[str],
    signed_time_override: Any = None,
) -> Mapping[str, Any] | None:
    """Verify an envelope whose signer may live in an accepted historic ring."""

    projection = copy.deepcopy(dict(document))
    projection[digest_field] = None
    projection[signature_field] = None
    try:
        projection_bytes = canonical_json_bytes(projection)
    except (CanonicalizationError, TypeError, ValueError) as exc:
        errors.append(f"{label}: cannot canonicalize signed projection: {exc}")
        return None
    expected_digest = sha256(projection_bytes)
    if document.get(digest_field) != expected_digest:
        errors.append(
            f"{label}.{digest_field}: declared {document.get(digest_field)!r}, "
            f"actual {expected_digest}"
        )
    ring, key = _trust_key_at_history_version(
        trust,
        document.get("keyRingVersion"),
        document.get(signer_field),
        evidence_git,
        root,
        label,
        errors,
    )
    if not isinstance(key, Mapping):
        return None
    roles = key.get("roles")
    if not isinstance(roles, list) or required_role not in roles:
        errors.append(f"{label}: signer key lacks required role {required_role}")
    signed_at = _parse_time(
        (
            signed_time_override
            if signed_time_override is not None
            else document.get(signed_time_field)
        ),
        f"{label}.{signed_time_field}",
        errors,
    )
    key_before = _parse_time(key.get("notBefore"), f"{label}.signer.notBefore", errors)
    key_after = _parse_time(key.get("notAfter"), f"{label}.signer.notAfter", errors)
    revoked_at = (
        _parse_time(
            key.get("revokedAtOrNull"), f"{label}.signer.revokedAt", errors
        )
        if key.get("revokedAtOrNull") is not None
        else None
    )
    ring_before = (
        _parse_time(ring.get("notBefore"), f"{label}.ring.notBefore", errors)
        if isinstance(ring, Mapping)
        else None
    )
    ring_after = (
        _parse_time(ring.get("expiresAt"), f"{label}.ring.expiresAt", errors)
        if isinstance(ring, Mapping)
        else None
    )
    if signed_at is not None:
        if (
            key_before is not None
            and key_after is not None
            and not (key_before <= signed_at < key_after)
        ):
            errors.append(f"{label}: signer key was not valid at signed time")
        if (
            ring_before is not None
            and ring_after is not None
            and not (ring_before <= signed_at < ring_after)
        ):
            errors.append(f"{label}: key ring was not valid at signed time")
        if revoked_at is not None and signed_at >= revoked_at:
            errors.append(f"{label}: signer key was revoked at signed time")
    _verify_ed25519(
        key.get("publicKeyBase64Url"),
        document.get(signature_field),
        domain.encode("ascii") + b"\x00" + projection_bytes,
        label,
        errors,
    )
    return key


def _validate_build_attestation(
    descriptor: Any,
    *,
    expected_consumer_kind: str,
    expected_consumer_build_id: Any,
    expected_target_commit: Any,
    expected_mapping_core_id: Any,
    expected_portable_contract_sha256: Any,
    expected_source_tree: Mapping[str, Any] | None,
    code_git: _GitView | None,
    evidence_git: _GitView | None,
    root: Path,
    trust: _TrustContext | None,
    label: str,
    errors: list[str],
) -> dict[str, Any] | None:
    """Recursively validate one signed, consumer-independent build closure."""

    blob = _typed_artifact_from_git(
        descriptor,
        evidence_git,
        root,
        label,
        errors,
        expected_schema_ref="contracts/directpath-build-attestation.schema.json",
        descriptor_fields=BUILD_ATTESTATION_DESCRIPTOR_FIELDS,
    )
    if not isinstance(descriptor, Mapping) or blob is None:
        return None
    if descriptor.get("mediaType") != "application/json":
        errors.append(f"{label}.mediaType: expected application/json")
    if descriptor.get("byteLength") != len(blob):
        errors.append(
            f"{label}.byteLength: declared {descriptor.get('byteLength')!r}, "
            f"actual {len(blob)}"
        )
    attestation = _load_json_bytes(blob, label, errors)
    if not isinstance(attestation, Mapping):
        return None
    outer_signer_key = _verify_history_signed_envelope(
        attestation,
        digest_field="attestationDigest",
        signature_field="signature",
        signer_field="signerKeyId",
        signed_time_field="attestedAt",
        domain="QMAN-DIRECTPATH/BUILD-ATTESTATION/V1",
        required_role="TEST_EVIDENCE",
        trust=trust,
        evidence_git=evidence_git,
        root=root,
        label=label,
        errors=errors,
    )
    if descriptor.get("attestationDigest") != attestation.get("attestationDigest"):
        errors.append(f"{label}.attestationDigest: parsed attestation mismatch")
    exact_fields = {
        "consumerKind": expected_consumer_kind,
        "consumerBuildId": expected_consumer_build_id,
        "targetRepositoryCommit": expected_target_commit,
        "mappingCoreId": expected_mapping_core_id,
        "portableContractSha256": expected_portable_contract_sha256,
    }
    for field, expected in exact_fields.items():
        if attestation.get(field) != expected:
            errors.append(f"{label}.{field}: expected exact consumer value {expected!r}")

    source_tree = attestation.get("sourceTree")
    tracked_paths: set[str] = set()
    tracked_entries: dict[str, Mapping[str, Any]] = {}
    source_blob: bytes | None = None
    if isinstance(source_tree, Mapping):
        source_blob = (
            evidence_git.blob(source_tree.get("path"), f"{label}.sourceTree.path", errors)
            if evidence_git is not None
            else None
        )
        _check_blob_hash(
            source_blob,
            source_tree.get("sha256"),
            f"{label}.sourceTree",
            errors,
        )
        if source_blob is not None and source_tree.get("byteLength") != len(source_blob):
            errors.append(
                f"{label}.sourceTree.byteLength: declared "
                f"{source_tree.get('byteLength')!r}, actual {len(source_blob)}"
            )
        if source_tree.get("mediaType") != "application/json":
            errors.append(f"{label}.sourceTree.mediaType: expected application/json")
        expected_common = expected_source_tree or {}
        for field, expected in expected_common.items():
            if source_tree.get(field) != expected:
                errors.append(
                    f"{label}.sourceTree.{field}: consumer/source-tree mismatch"
                )
        _validate_source_tree_manifest(
            {
                "sourceTreeManifestPath": source_tree.get("path"),
                "sourceTreeManifestSha256": source_tree.get("sha256"),
                "sourceTreeManifestSchemaSha256": source_tree.get("schemaSha256"),
                "sourceTreeSha256": source_tree.get("sourceTreeSha256"),
            },
            code_git,
            evidence_git,
            root,
            f"{label}.sourceTree",
            errors,
            _tracked_paths=tracked_paths,
            _tracked_entries=tracked_entries,
        )
    else:
        errors.append(f"{label}.sourceTree: expected descriptor")

    artifacts: list[tuple[str, Mapping[str, Any], bytes | None]] = []

    def add_artifact(role: str, artifact: Any) -> bytes | None:
        artifact_blob = _validate_build_artifact(
            artifact, evidence_git, f"{label}.{role}", errors
        )
        if isinstance(artifact, Mapping):
            artifacts.append((role, artifact, artifact_blob))
        return artifact_blob

    builder = attestation.get("builder")
    if isinstance(builder, Mapping):
        add_artifact("builder.executable", builder.get("executable"))
        add_artifact("builder.configuration", builder.get("configuration"))

    toolchain = attestation.get("toolchain")
    components_by_id: dict[str, Mapping[str, Any]] = {}
    if isinstance(toolchain, Mapping):
        add_artifact("toolchain.manifest", toolchain.get("manifest"))
        components = toolchain.get("components")
        components_by_id = _validate_identifier_order(
            components, "componentId", f"{label}.toolchain.components", errors
        )
        for number, component in enumerate(
            components if isinstance(components, list) else []
        ):
            if isinstance(component, Mapping):
                add_artifact(
                    f"toolchain.components[{number}].artifact",
                    component.get("artifact"),
                )
        toolchain_projection = {
            "manifest": toolchain.get("manifest"),
            "components": components,
        }
        expected_toolchain_digest = _domain_projection_digest(
            "QMAN-DIRECTPATH/BUILD-ATTESTATION/TOOLCHAIN-CLOSURE/V1",
            toolchain_projection,
            f"{label}.toolchain.toolchainClosureSha256",
            errors,
        )
        if toolchain.get("toolchainClosureSha256") != expected_toolchain_digest:
            errors.append(
                f"{label}.toolchain.toolchainClosureSha256: closure digest mismatch"
            )
    else:
        errors.append(f"{label}.toolchain: expected object")

    dependencies = attestation.get("dependencies")
    if isinstance(dependencies, Mapping):
        add_artifact("dependencies.lockArtifact", dependencies.get("lockArtifact"))
        add_artifact(
            "dependencies.closureManifest", dependencies.get("closureManifest")
        )
        resolved = dependencies.get("resolvedArtifacts")
        _validate_identifier_order(
            resolved,
            "artifactId",
            f"{label}.dependencies.resolvedArtifacts",
            errors,
        )
        for number, named in enumerate(resolved if isinstance(resolved, list) else []):
            if isinstance(named, Mapping):
                add_artifact(
                    f"dependencies.resolvedArtifacts[{number}].artifact",
                    named.get("artifact"),
                )
        dependency_projection = {
            "lockArtifact": dependencies.get("lockArtifact"),
            "closureManifest": dependencies.get("closureManifest"),
            "resolvedArtifacts": resolved,
        }
        expected_dependency_digest = _domain_projection_digest(
            "QMAN-DIRECTPATH/BUILD-ATTESTATION/DEPENDENCY-CLOSURE/V1",
            dependency_projection,
            f"{label}.dependencies.dependencyClosureSha256",
            errors,
        )
        if dependencies.get("dependencyClosureSha256") != expected_dependency_digest:
            errors.append(
                f"{label}.dependencies.dependencyClosureSha256: closure digest mismatch"
            )
    else:
        errors.append(f"{label}.dependencies: expected object")

    environment = attestation.get("environment")
    if isinstance(environment, Mapping):
        add_artifact("environment.manifest", environment.get("manifest"))
    else:
        errors.append(f"{label}.environment: expected object")

    external_inputs = attestation.get("declaredExternalInputs")
    external_by_id = _validate_identifier_order(
        external_inputs,
        "externalInputId",
        f"{label}.declaredExternalInputs",
        errors,
    )
    for number, external in enumerate(
        external_inputs if isinstance(external_inputs, list) else []
    ):
        if not isinstance(external, Mapping):
            continue
        capture = external.get("captureArtifact")
        if isinstance(capture, Mapping):
            add_artifact(
                f"declaredExternalInputs[{number}].captureArtifact", capture
            )
            exact_capture = {
                "sha256": external.get("contentSha256"),
                "byteLength": external.get("byteLength"),
                "mediaType": external.get("mediaType"),
            }
            for field, expected in exact_capture.items():
                if capture.get(field) != expected:
                    errors.append(
                        f"{label}.declaredExternalInputs[{number}].captureArtifact."
                        f"{field}: external-input content mismatch"
                    )
        elif external.get("availability") != "HASH_ONLY_SECRET":
            errors.append(
                f"{label}.declaredExternalInputs[{number}].captureArtifact: "
                "archived input requires exact captured bytes"
            )

    output = attestation.get("output")
    if isinstance(output, Mapping) and output.get("kind") == "PRODUCED_ARTIFACT":
        add_artifact("output.artifact", output.get("artifact"))
    add_artifact("buildLog", attestation.get("buildLog"))

    invocation = attestation.get("canonicalInvocation")
    if isinstance(invocation, Mapping):
        argv = invocation.get("argv")
        if not isinstance(argv, list) or not argv or not isinstance(argv[0], str) or not argv[0]:
            errors.append(f"{label}.canonicalInvocation.argv[0]: must be non-empty")
        cwd = invocation.get("cwd")
        if isinstance(cwd, str) and cwd != ".":
            cwd_prefix = f"{cwd}/"
            if not any(path.startswith(cwd_prefix) for path in tracked_paths):
                errors.append(
                    f"{label}.canonicalInvocation.cwd: is not a tracked source-tree directory"
                )
        bindings = invocation.get("environmentAllowlist")
        environment_by_name = _validate_identifier_order(
            bindings,
            "name",
            f"{label}.canonicalInvocation.environmentAllowlist",
            errors,
        )
        referenced_external_ids: set[str] = set()
        for name, binding in environment_by_name.items():
            if binding.get("valueSource") == "FIXED_LITERAL_UTF8":
                literal = binding.get("literalValue")
                if isinstance(literal, str):
                    literal_bytes = literal.encode("utf-8")
                    if binding.get("valueSha256") != sha256(literal_bytes):
                        errors.append(
                            f"{label}.canonicalInvocation.environmentAllowlist[{name}]."
                            "valueSha256: literal digest mismatch"
                        )
                    if binding.get("valueByteLength") != len(literal_bytes):
                        errors.append(
                            f"{label}.canonicalInvocation.environmentAllowlist[{name}]."
                            "valueByteLength: literal length mismatch"
                        )
            elif binding.get("valueSource") == "DECLARED_EXTERNAL_INPUT":
                external_id = binding.get("externalInputId")
                if isinstance(external_id, str):
                    referenced_external_ids.add(external_id)
                    external = external_by_id.get(external_id)
                else:
                    external = None
                if external is None:
                    errors.append(
                        f"{label}.canonicalInvocation.environmentAllowlist[{name}]: "
                        "unknown externalInputId"
                    )
                else:
                    for binding_field, external_field in (
                        ("valueSha256", "contentSha256"),
                        ("valueByteLength", "byteLength"),
                    ):
                        if binding.get(binding_field) != external.get(external_field):
                            errors.append(
                                f"{label}.canonicalInvocation.environmentAllowlist[{name}]."
                                f"{binding_field}: external input mismatch"
                            )
        del referenced_external_ids
    else:
        errors.append(f"{label}.canonicalInvocation: expected object")

    mode = attestation.get("mode")
    if mode == "INTERPRETED_NO_BUILD" and isinstance(output, Mapping):
        entrypoint = output.get("entrypointSource")
        if isinstance(entrypoint, Mapping):
            path = entrypoint.get("path")
            tracked = tracked_entries.get(path) if isinstance(path, str) else None
            if tracked is None or tracked.get("mode") not in {"100644", "100755"}:
                errors.append(
                    f"{label}.output.entrypointSource: not one regular source-tree entry"
                )
            else:
                exact_entry = {
                    "gitObjectId": tracked.get("gitObjectId"),
                    "contentSha256": tracked.get("contentSha256"),
                    "byteLength": tracked.get("byteLength"),
                }
                for field, expected in exact_entry.items():
                    if entrypoint.get(field) != expected:
                        errors.append(
                            f"{label}.output.entrypointSource.{field}: tracked-tree mismatch"
                        )
            entrypoint_blob = (
                code_git.blob(path, f"{label}.output.entrypointSource.path", errors)
                if code_git is not None
                else None
            )
            _check_blob_hash(
                entrypoint_blob,
                entrypoint.get("contentSha256"),
                f"{label}.output.entrypointSource",
                errors,
            )
            if entrypoint_blob is not None and entrypoint.get("byteLength") != len(
                entrypoint_blob
            ):
                errors.append(f"{label}.output.entrypointSource.byteLength: mismatch")
        interpreter_id = output.get("interpreterComponentId")
        interpreter = (
            components_by_id.get(interpreter_id)
            if isinstance(interpreter_id, str)
            else None
        )
        if interpreter is None or interpreter.get("role") != "INTERPRETER":
            errors.append(
                f"{label}.output.interpreterComponentId: does not resolve the "
                "unique INTERPRETER component"
            )
        else:
            interpreter_artifact = interpreter.get("artifact")
            if not isinstance(interpreter_artifact, Mapping) or output.get(
                "interpreterArtifactSha256"
            ) != interpreter_artifact.get("sha256"):
                errors.append(
                    f"{label}.output.interpreterArtifactSha256: component mismatch"
                )
        if isinstance(dependencies, Mapping):
            lock = dependencies.get("lockArtifact")
            if not isinstance(lock, Mapping) or output.get(
                "dependencyLockSha256"
            ) != lock.get("sha256"):
                errors.append(f"{label}.output.dependencyLockSha256: lock mismatch")
        runtime_projection = {
            "entrypointSource": output.get("entrypointSource"),
            "interpreterComponentId": output.get("interpreterComponentId"),
            "interpreterArtifactSha256": output.get("interpreterArtifactSha256"),
            "dependencyLockSha256": output.get("dependencyLockSha256"),
        }
        expected_runtime_digest = _domain_projection_digest(
            "QMAN-DIRECTPATH/INTERPRETED-RUNTIME/V1",
            runtime_projection,
            f"{label}.output.runtimeIdentitySha256",
            errors,
        )
        if output.get("runtimeIdentitySha256") != expected_runtime_digest:
            errors.append(f"{label}.output.runtimeIdentitySha256: digest mismatch")

    if isinstance(invocation, Mapping):
        argv = invocation.get("argv")
        argv_zero = argv[0] if isinstance(argv, list) and argv else None
        expected_executable_path: Any = None
        if mode in {"HERMETIC_REPRODUCIBLE", "PINNED_NONHERMETIC"}:
            executable = builder.get("executable") if isinstance(builder, Mapping) else None
            if isinstance(executable, Mapping):
                expected_executable_path = executable.get("path")
        elif mode == "INTERPRETED_NO_BUILD" and isinstance(output, Mapping):
            interpreter_id = output.get("interpreterComponentId")
            interpreter = (
                components_by_id.get(interpreter_id)
                if isinstance(interpreter_id, str)
                else None
            )
            interpreter_artifact = (
                interpreter.get("artifact") if isinstance(interpreter, Mapping) else None
            )
            if isinstance(interpreter_artifact, Mapping):
                expected_executable_path = interpreter_artifact.get("path")
        if argv_zero != expected_executable_path:
            errors.append(
                f"{label}.canonicalInvocation.argv[0]: must exactly resolve the "
                "declared builder/interpreter executable; ambient PATH is forbidden"
            )

    replay_evidence = attestation.get("replayEvidence")
    replay_by_id = _validate_identifier_order(
        replay_evidence,
        "replayId",
        f"{label}.replayEvidence",
        errors,
    )
    if mode == "HERMETIC_REPRODUCIBLE":
        if not replay_by_id:
            errors.append(
                f"{label}.replayEvidence: hermetic mode requires an independent replay"
            )
    elif replay_by_id or (isinstance(replay_evidence, list) and replay_evidence):
        errors.append(f"{label}.replayEvidence: non-hermetic mode requires []")

    invocation_digest = _domain_projection_digest(
        "QMAN-DIRECTPATH/BUILD-ATTESTATION/CANONICAL-INVOCATION/V1",
        invocation,
        f"{label}.canonicalInvocationSha256",
        errors,
    )
    output_artifact = (
        output.get("artifact")
        if isinstance(output, Mapping)
        and output.get("kind") == "PRODUCED_ARTIFACT"
        else None
    )
    original_output_hash = (
        output_artifact.get("sha256")
        if isinstance(output_artifact, Mapping)
        else None
    )
    outer_principal = (
        outer_signer_key.get("principalId")
        if isinstance(outer_signer_key, Mapping)
        else None
    )
    original_finished = _parse_time(
        attestation.get("finishedAt"), f"{label}.finishedAt", errors
    )
    attested_at = _parse_time(
        attestation.get("attestedAt"), f"{label}.attestedAt", errors
    )
    replay_unique_fields = {
        "executorPrincipalId": set(),
        "executorKeyId": set(),
        "instanceId": set(),
        "replayBuildLog.path": set(),
        "replayBuildLog.sha256": set(),
        "receiptDigest": set(),
        "signature": set(),
    }
    environment_manifest = (
        environment.get("manifest") if isinstance(environment, Mapping) else None
    )
    builder_instance_id = (
        environment.get("builderInstanceId")
        if isinstance(environment, Mapping)
        else None
    )
    for number, receipt in enumerate(
        replay_evidence if isinstance(replay_evidence, list) else []
    ):
        receipt_label = f"{label}.replayEvidence[{number}]"
        if not isinstance(receipt, Mapping):
            continue
        exact_receipt_fields = {
            "buildAttestationId": attestation.get("attestationId"),
            "targetRepositoryCommit": attestation.get("targetRepositoryCommit"),
            "mappingCoreId": attestation.get("mappingCoreId"),
            "portableContractSha256": attestation.get("portableContractSha256"),
            "sourceTreeSha256": (
                source_tree.get("sourceTreeSha256")
                if isinstance(source_tree, Mapping)
                else None
            ),
            "canonicalInvocationSha256": invocation_digest,
            "toolchainClosureSha256": (
                toolchain.get("toolchainClosureSha256")
                if isinstance(toolchain, Mapping)
                else None
            ),
            "dependencyClosureSha256": (
                dependencies.get("dependencyClosureSha256")
                if isinstance(dependencies, Mapping)
                else None
            ),
            "environmentManifestSha256": (
                environment_manifest.get("sha256")
                if isinstance(environment_manifest, Mapping)
                else None
            ),
            "originalOutputSha256": original_output_hash,
            "replayedOutputSha256": original_output_hash,
            "result": "BYTE_IDENTICAL",
        }
        for field, expected in exact_receipt_fields.items():
            if receipt.get(field) != expected:
                errors.append(f"{receipt_label}.{field}: enclosing build mismatch")

        receipt_projection = copy.deepcopy(dict(receipt))
        receipt_projection["receiptDigest"] = None
        receipt_projection["signature"] = None
        try:
            receipt_preimage = (
                b"QMAN-DIRECTPATH/BUILD-ATTESTATION/REPLAY-RECEIPT/V1\x00"
                + canonical_json_bytes(receipt_projection)
            )
        except (CanonicalizationError, TypeError, ValueError) as exc:
            errors.append(f"{receipt_label}: cannot canonicalize receipt: {exc}")
            receipt_preimage = None
        if receipt_preimage is not None:
            expected_receipt_digest = sha256(receipt_preimage)
            if receipt.get("receiptDigest") != expected_receipt_digest:
                errors.append(f"{receipt_label}.receiptDigest: digest mismatch")

        ring, executor_key = _trust_key_at_history_version(
            trust,
            receipt.get("keyRingVersion"),
            receipt.get("executorKeyId"),
            evidence_git,
            root,
            receipt_label,
            errors,
        )
        if isinstance(executor_key, Mapping):
            if "TEST_EVIDENCE" not in executor_key.get("roles", []):
                errors.append(f"{receipt_label}: executor key lacks TEST_EVIDENCE")
            if executor_key.get("principalId") != receipt.get("executorPrincipalId"):
                errors.append(
                    f"{receipt_label}.executorPrincipalId: key principal mismatch"
                )
            if receipt.get("executorPrincipalId") == outer_principal:
                errors.append(
                    f"{receipt_label}.executorPrincipalId: replay principal must be "
                    "independent from the BuildAttestation signer"
                )
            if receipt.get("executorKeyId") == attestation.get("signerKeyId"):
                errors.append(
                    f"{receipt_label}.executorKeyId: replay and build signer keys "
                    "must differ"
                )
            if receipt_preimage is not None:
                _verify_ed25519(
                    executor_key.get("publicKeyBase64Url"),
                    receipt.get("signature"),
                    receipt_preimage,
                    receipt_label,
                    errors,
                )

        replay_started = _parse_time(
            receipt.get("startedAt"), f"{receipt_label}.startedAt", errors
        )
        replay_finished = _parse_time(
            receipt.get("finishedAt"), f"{receipt_label}.finishedAt", errors
        )
        if replay_started is not None and replay_finished is not None:
            if replay_started > replay_finished:
                errors.append(f"{receipt_label}: startedAt must not follow finishedAt")
            if original_finished is not None and replay_started < original_finished:
                errors.append(
                    f"{receipt_label}.startedAt: replay overlaps original build"
                )
            if attested_at is not None and replay_finished > attested_at:
                errors.append(
                    f"{receipt_label}.finishedAt: replay follows outer attestation"
                )
        if isinstance(executor_key, Mapping):
            key_before = _parse_time(
                executor_key.get("notBefore"),
                f"{receipt_label}.executor.notBefore",
                errors,
            )
            key_after = _parse_time(
                executor_key.get("notAfter"),
                f"{receipt_label}.executor.notAfter",
                errors,
            )
            revoked_at = (
                _parse_time(
                    executor_key.get("revokedAtOrNull"),
                    f"{receipt_label}.executor.revokedAt",
                    errors,
                )
                if executor_key.get("revokedAtOrNull") is not None
                else None
            )
            for time_name, observed in (
                ("startedAt", replay_started),
                ("finishedAt", replay_finished),
            ):
                if (
                    observed is not None
                    and key_before is not None
                    and key_after is not None
                    and not (key_before <= observed < key_after)
                ):
                    errors.append(
                        f"{receipt_label}.{time_name}: outside executor key validity"
                    )
                if observed is not None and revoked_at is not None and observed >= revoked_at:
                    errors.append(
                        f"{receipt_label}.{time_name}: executor key was revoked"
                    )
        if isinstance(ring, Mapping):
            ring_before = _parse_time(
                ring.get("notBefore"), f"{receipt_label}.ring.notBefore", errors
            )
            ring_after = _parse_time(
                ring.get("expiresAt"), f"{receipt_label}.ring.expiresAt", errors
            )
            for time_name, observed in (
                ("startedAt", replay_started),
                ("finishedAt", replay_finished),
            ):
                if (
                    observed is not None
                    and ring_before is not None
                    and ring_after is not None
                    and not (ring_before <= observed < ring_after)
                ):
                    errors.append(
                        f"{receipt_label}.{time_name}: outside key-ring validity"
                    )

        clean_environment = receipt.get("cleanEnvironmentInstance")
        if isinstance(clean_environment, Mapping):
            instance_id = clean_environment.get("instanceId")
            if instance_id == builder_instance_id:
                errors.append(
                    f"{receipt_label}.cleanEnvironmentInstance.instanceId: "
                    "must differ from original builder instance"
                )
            add_artifact(
                f"replayEvidence[{number}].cleanEnvironmentInstance."
                "provisioningManifest",
                clean_environment.get("provisioningManifest"),
            )
            add_artifact(
                f"replayEvidence[{number}].cleanEnvironmentInstance."
                "cleanStateEvidence",
                clean_environment.get("cleanStateEvidence"),
            )
        replay_log = receipt.get("replayBuildLog")
        add_artifact(f"replayEvidence[{number}].replayBuildLog", replay_log)

        unique_values = {
            "executorPrincipalId": receipt.get("executorPrincipalId"),
            "executorKeyId": receipt.get("executorKeyId"),
            "instanceId": (
                clean_environment.get("instanceId")
                if isinstance(clean_environment, Mapping)
                else None
            ),
            "replayBuildLog.path": (
                replay_log.get("path") if isinstance(replay_log, Mapping) else None
            ),
            "replayBuildLog.sha256": (
                replay_log.get("sha256") if isinstance(replay_log, Mapping) else None
            ),
            "receiptDigest": receipt.get("receiptDigest"),
            "signature": receipt.get("signature"),
        }
        for field, value in unique_values.items():
            if not isinstance(value, str):
                continue
            seen = replay_unique_fields[field]
            if value in seen:
                errors.append(f"{receipt_label}.{field}: duplicate replay identity")
            seen.add(value)

    role_descriptors: list[tuple[str, Mapping[str, Any]]] = []
    if isinstance(source_tree, Mapping):
        role_descriptors.append(("sourceTree", source_tree))
    role_descriptors.extend((role, item) for role, item, _ in artifacts)
    path_owners: dict[str, str] = {}
    hash_owners: dict[str, str] = {}
    for role, item in role_descriptors:
        for field, owners in (("path", path_owners), ("sha256", hash_owners)):
            value = item.get(field)
            if not isinstance(value, str):
                continue
            previous = owners.get(value)
            if previous is not None and previous != role:
                errors.append(
                    f"{label}: {field} {value!r} silently reuses roles "
                    f"{previous} and {role}"
                )
            else:
                owners[value] = role
    for field, owners in (("path", path_owners), ("sha256", hash_owners)):
        value = descriptor.get(field)
        if isinstance(value, str) and value in owners:
            errors.append(
                f"{label}: BuildAttestation {field} reuses nested role {owners[value]}"
            )

    started = _parse_time(attestation.get("startedAt"), f"{label}.startedAt", errors)
    finished = _parse_time(attestation.get("finishedAt"), f"{label}.finishedAt", errors)
    if started is not None and finished is not None and started > finished:
        errors.append(f"{label}: startedAt must not follow finishedAt")
    if finished is not None and attested_at is not None and finished > attested_at:
        errors.append(f"{label}: finishedAt must not follow attestedAt")

    return {
        "attestation": attestation,
        "artifacts": {role: item for role, item, _ in artifacts},
        "trackedPaths": tracked_paths,
        "trackedEntries": tracked_entries,
        "sourceBlob": source_blob,
    }


def _validate_runner_manifest(
    scenario: Mapping[str, Any],
    result: Mapping[str, Any],
    root: Path,
    code_git: _GitView | None,
    evidence_git: _GitView | None,
    mapping: Mapping[str, Any] | None,
    trust: _TrustContext | None,
    case_registry: Mapping[str, Any] | None,
    case_record: Mapping[str, Any] | None,
    errors: list[str],
) -> Mapping[str, Any] | None:
    target = scenario.get("targetBinding", {})
    if not isinstance(target, Mapping):
        return None
    path = target.get("runnerManifestPath")
    if result.get("runnerManifestPath") != path:
        errors.append(
            "scenario.executionResult.runnerManifestPath: must equal targetBinding"
        )
    blob = (
        evidence_git.blob(path, "scenario.targetBinding.runnerManifestPath", errors)
        if evidence_git
        else None
    )
    _check_blob_hash(
        blob,
        target.get("runnerManifestSha256"),
        "scenario.targetBinding.runnerManifest",
        errors,
    )
    manifest = (
        _load_json_bytes(blob, "RunnerManifest", errors) if blob is not None else None
    )
    if not isinstance(manifest, Mapping):
        return None
    _validate_closed_json_schema_instance(
        manifest,
        root,
        "contracts/directpath-runner-manifest.schema.json",
        "RunnerManifest",
        errors,
    )
    _verify_signed_envelope(
        manifest,
        digest_field="manifestDigest",
        signature_field="signature",
        signer_field="signerKeyId",
        signed_time_field="createdAt",
        domain="QMAN-DIRECTPATH/RUNNER-MANIFEST/V1",
        required_role="TEST_EVIDENCE",
        trust=trust,
        label="RunnerManifest",
        errors=errors,
    )
    exact = {
        "targetRepositoryCommit": target.get("repositoryCommit"),
        "mappingCoreId": target.get("mappingCoreId"),
        "portableContractSha256": target.get("portableContractSha256"),
    }
    for field, expected in exact.items():
        if manifest.get(field) != expected:
            errors.append(f"RunnerManifest.{field}: expected {expected!r}")
    if result.get("runnerManifestDigest") != manifest.get("manifestDigest"):
        errors.append(
            "scenario.executionResult.runnerManifestDigest: does not equal signed "
            "RunnerManifest digest"
        )
    registry_blob = _worktree_bytes(
        root,
        CASE_CONTRACT_REGISTRY_PATH,
        "RunnerManifest Case registry",
        errors,
    )
    if registry_blob is not None and manifest.get("caseContractRegistrySha256") != sha256(
        registry_blob
    ):
        errors.append(
            "RunnerManifest.caseContractRegistrySha256: does not hash the exact "
            "independently validated registry bytes"
        )

    runner = manifest.get("runner")
    if isinstance(runner, Mapping):
        runner_blob = (
            code_git.blob(runner.get("path"), "RunnerManifest.runner.path", errors)
            if code_git
            else None
        )
        _check_blob_hash(
            runner_blob,
            runner.get("blobSha256"),
            "RunnerManifest.runner source",
            errors,
        )
        matches = _target_symbol_matches(
            mapping,
            path=runner.get("path"),
            symbol=runner.get("symbol"),
            interface_hash=runner.get("interfaceHash"),
        )
        if len(matches) != 1:
            errors.append(
                "RunnerManifest.runner: path/symbol/interface must resolve exactly "
                f"one signed target symbol binding, found {len(matches)}"
            )
        if result.get("runnerSha256") != runner.get("binaryArtifactSha256"):
            errors.append(
                "scenario.executionResult.runnerSha256: must equal RunnerManifest "
                "runner.binaryArtifactSha256"
            )

    build = manifest.get("build")
    if isinstance(build, Mapping):
        if build.get("buildId") != target.get("buildId"):
            errors.append("RunnerManifest.build.buildId: must equal targetBinding.buildId")
        tracked_paths: set[str] = set()
        source_tree_manifest = _validate_source_tree_manifest(
            build,
            code_git,
            evidence_git,
            root,
            "RunnerManifest.build",
            errors,
            _tracked_paths=tracked_paths,
        )
        if isinstance(source_tree_manifest, Mapping):
            implementation_paths = {
                runner.get("path") if isinstance(runner, Mapping) else None,
                *(
                    item.get("path")
                    for mapping_item in (
                        mapping.get("mappings", [])
                        if isinstance(mapping, Mapping)
                        else []
                    )
                    if isinstance(mapping_item, Mapping)
                    for item in mapping_item.get("targetBindings", [])
                    if isinstance(item, Mapping)
                ),
            }
            missing_paths = {
                path
                for path in implementation_paths
                if isinstance(path, str) and path not in tracked_paths
            }
            if missing_paths:
                errors.append(
                    "RunnerManifest.build.sourceTreeManifest: mapped implementation "
                    f"paths are absent from the complete tree {sorted(missing_paths)}"
                )
        build_bundle = _validate_build_attestation(
            build.get("buildAttestation"),
            expected_consumer_kind="RUNNER",
            expected_consumer_build_id=build.get("buildId"),
            expected_target_commit=manifest.get("targetRepositoryCommit"),
            expected_mapping_core_id=manifest.get("mappingCoreId"),
            expected_portable_contract_sha256=manifest.get(
                "portableContractSha256"
            ),
            expected_source_tree={
                "path": build.get("sourceTreeManifestPath"),
                "sha256": build.get("sourceTreeManifestSha256"),
                "schemaRef": "contracts/directpath-source-tree-manifest.schema.json",
                "schemaSha256": build.get("sourceTreeManifestSchemaSha256"),
                "sourceTreeSha256": build.get("sourceTreeSha256"),
            },
            code_git=code_git,
            evidence_git=evidence_git,
            root=root,
            trust=trust,
            label="RunnerManifest.build.buildAttestation",
            errors=errors,
        )
        if isinstance(build_bundle, Mapping):
            attestation = build_bundle.get("attestation")
            build_artifacts = build_bundle.get("artifacts")
            if isinstance(attestation, Mapping):
                mode_mapping = {
                    "HERMETIC_REPRODUCIBLE": "HERMETIC_REPRODUCIBLE",
                    "PINNED_NONHERMETIC": (
                        "PINNED_NONHERMETIC_WITH_COMPLETE_MANIFEST"
                    ),
                }
                expected_reproducibility = mode_mapping.get(attestation.get("mode"))
                if expected_reproducibility is None:
                    errors.append(
                        "RunnerManifest.build.buildAttestation.mode: product runner "
                        "requires a produced HERMETIC_REPRODUCIBLE or "
                        "PINNED_NONHERMETIC build"
                    )
                elif build.get("reproducibility") != expected_reproducibility:
                    errors.append(
                        "RunnerManifest.build.reproducibility: BuildAttestation "
                        "mode mismatch"
                    )
                output = attestation.get("output")
                if (
                    not isinstance(output, Mapping)
                    or output.get("kind") != "PRODUCED_ARTIFACT"
                    or output.get("role") != "RUNNER_BINARY"
                    or output.get("executable") is not True
                ):
                    errors.append(
                        "RunnerManifest.build.buildAttestation.output: expected "
                        "executable produced RUNNER_BINARY"
                    )
                elif isinstance(runner, Mapping):
                    output_artifact = output.get("artifact")
                    if not isinstance(output_artifact, Mapping) or output_artifact.get(
                        "sha256"
                    ) != runner.get("binaryArtifactSha256"):
                        errors.append(
                            "RunnerManifest.runner.binaryArtifactSha256: "
                            "BuildAttestation output mismatch"
                        )
                attested_finished = _parse_time(
                    attestation.get("attestedAt"),
                    "RunnerManifest.build.buildAttestation.attestedAt",
                    errors,
                )
                manifest_created = _parse_time(
                    manifest.get("createdAt"), "RunnerManifest.createdAt", errors
                )
                if (
                    attested_finished is not None
                    and manifest_created is not None
                    and attested_finished >= manifest_created
                ):
                    errors.append(
                        "RunnerManifest.createdAt: must strictly follow complete "
                        "BuildAttestation"
                    )
            if isinstance(build_artifacts, Mapping):
                expected_build_artifacts = {
                    "toolchain.manifest": build.get("toolManifestArtifactSha256"),
                    "buildLog": build.get("buildLogArtifactSha256"),
                    "environment.manifest": build.get(
                        "builderImageOrEnvironmentSha256"
                    ),
                }
                for role, expected_hash in expected_build_artifacts.items():
                    artifact = build_artifacts.get(role)
                    if not isinstance(artifact, Mapping) or artifact.get(
                        "sha256"
                    ) != expected_hash:
                        errors.append(
                            f"RunnerManifest.build.{role}: BuildAttestation "
                            "artifact mismatch"
                        )

    registry_records = {
        item.get("caseId"): item
        for item in (
            case_registry.get("records", [])
            if isinstance(case_registry, Mapping)
            else []
        )
        if isinstance(item, Mapping)
        and isinstance(item.get("caseId"), str)
    }
    predicates = manifest.get("predicateEvaluators")
    if not isinstance(predicates, list):
        predicates = []
    predicate_keys: list[bytes] = []
    seen_predicates: set[tuple[Any, Any]] = set()
    predicate_by_id: dict[tuple[Any, Any], Mapping[str, Any]] = {}
    for index, predicate in enumerate(predicates):
        label = f"RunnerManifest.predicateEvaluators[{index}]"
        if not isinstance(predicate, Mapping):
            continue
        case_id = predicate.get("caseId")
        assertion_id = predicate.get("assertionId")
        key = (
            (case_id, assertion_id)
            if isinstance(case_id, str) and isinstance(assertion_id, str)
            else None
        )
        try:
            predicate_keys.append(
                canonical_json_bytes([case_id, assertion_id])
            )
        except (CanonicalizationError, TypeError, ValueError) as exc:
            errors.append(f"{label}: invalid order key: {exc}")
        if key is None:
            errors.append(f"{label}: caseId/assertionId must be strings")
        else:
            if key in seen_predicates:
                errors.append(f"{label}: duplicate [caseId,assertionId]")
            seen_predicates.add(key)
            predicate_by_id[key] = predicate
        registry_case = (
            registry_records.get(case_id) if isinstance(case_id, str) else None
        )
        assertions = registry_case.get("assertions", []) if isinstance(registry_case, Mapping) else []
        assertion_matches = [
            assertion
            for assertion in assertions
            if isinstance(assertion, Mapping)
            and assertion.get("assertionId") == predicate.get("assertionId")
        ]
        if len(assertion_matches) != 1:
            errors.append(f"{label}: does not resolve one immutable Case assertion")
        else:
            assertion = assertion_matches[0]
            if predicate.get("assertionDigest") != assertion.get("assertionDigest"):
                errors.append(f"{label}.assertionDigest: immutable digest mismatch")
            if predicate.get("evaluatorProtocol") != assertion.get("predicateEvaluator"):
                errors.append(f"{label}.evaluatorProtocol: immutable protocol mismatch")
        matches = _target_symbol_matches(
            mapping,
            symbol=predicate.get("symbol"),
            interface_hash=predicate.get("interfaceHash"),
        )
        if len(matches) != 1:
            errors.append(
                f"{label}: predicate symbol/interface resolves {len(matches)} signed "
                "target bindings; expected exactly one"
            )
    if predicate_keys != sorted(predicate_keys):
        errors.append(
            "RunnerManifest.predicateEvaluators: must be ordered by canonical "
            "[caseId,assertionId]"
        )

    scenario_bindings = scenario.get("casePredicateBindings", [])
    if isinstance(case_record, Mapping) and isinstance(scenario_bindings, list):
        for index, binding in enumerate(scenario_bindings):
            if not isinstance(binding, Mapping):
                continue
            case_id = case_record.get("caseId")
            assertion_id = binding.get("assertionId")
            key = (
                (case_id, assertion_id)
                if isinstance(case_id, str) and isinstance(assertion_id, str)
                else None
            )
            predicate = predicate_by_id.get(key) if key is not None else None
            if predicate is None:
                errors.append(
                    f"RunnerManifest: missing scenario predicate {assertion_id!r}"
                )
                continue
            exact_binding = {
                "assertionDigest": binding.get("assertionDigest"),
                "symbol": binding.get("targetPredicateSymbolOrNull"),
                "interfaceHash": binding.get("targetPredicateInterfaceHashOrNull"),
                "evaluatorProtocol": binding.get("predicateEvaluator"),
            }
            for field, expected in exact_binding.items():
                if predicate.get(field) != expected:
                    errors.append(
                        f"RunnerManifest predicate {assertion_id}.{field}: scenario binding "
                        "mismatch"
                    )

    decoders = manifest.get("artifactDecoders")
    if not isinstance(decoders, list):
        decoders = []
    decoder_order: list[bytes] = []
    seen_schema_refs: set[str] = set()
    for index, decoder in enumerate(decoders):
        label = f"RunnerManifest.artifactDecoders[{index}]"
        if not isinstance(decoder, Mapping):
            continue
        schema_ref = decoder.get("schemaRef")
        if not isinstance(schema_ref, str):
            continue
        decoder_order.append(canonical_json_bytes(schema_ref))
        if schema_ref in seen_schema_refs:
            errors.append(f"{label}.schemaRef: duplicate decoder")
        seen_schema_refs.add(schema_ref)
        schema_path = schema_ref.split("#", 1)[0]
        schema_blob = _worktree_bytes(root, schema_path, f"{label}.schemaRef", errors)
        if schema_blob is not None and decoder.get("schemaSha256") != sha256(schema_blob):
            errors.append(f"{label}.schemaSha256: normative schema bytes mismatch")
        matches = _target_symbol_matches(
            mapping,
            symbol=decoder.get("symbol"),
            interface_hash=decoder.get("interfaceHash"),
        )
        if len(matches) != 1:
            errors.append(
                f"{label}: decoder symbol/interface resolves {len(matches)} signed "
                "target bindings; expected exactly one"
            )
    if decoder_order != sorted(decoder_order):
        errors.append(
            "RunnerManifest.artifactDecoders: must be ordered by canonical schemaRef"
        )
    if isinstance(case_record, Mapping):
        missing_decoders = set(case_record.get("requiredArtifactSchemaRefs", [])) - seen_schema_refs
        if missing_decoders:
            errors.append(
                "RunnerManifest.artifactDecoders: missing Case-required schemas "
                f"{sorted(missing_decoders)}"
            )
    return manifest


def _scenario_execution_core_digest(
    result: Mapping[str, Any], errors: list[str]
) -> str | None:
    projection = copy.deepcopy(dict(result))
    for field in (
        "resultDigest",
        "signature",
        "evidenceIndexRecordSha256",
        "executionEvidenceIndexDigest",
        "executionEvidenceIndexPath",
    ):
        projection[field] = None
    instances = projection.get("artifactInstances")
    if isinstance(instances, list):
        forbidden_types = {
            "RUNNER_MANIFEST",
            "EXECUTION_EVIDENCE_INDEX",
            "QUALIFICATION_SUBJECT",
        }
        forbidden = [
            item.get("artifactType")
            for item in instances
            if isinstance(item, Mapping)
            and item.get("artifactType") in forbidden_types
        ]
        if forbidden:
            errors.append(
                "scenario.executionResult.artifactInstances: run-global/self artifacts "
                f"are forbidden from the execution-core projection {forbidden}"
            )
    return _canonical_digest(
        projection, "scenario execution core projection", errors
    )


def _case_completion_observed_artifact_schema_refs(
    evidence_index: Mapping[str, Any],
) -> list[str]:
    """Derive observed schema coverage only from artifacts whose bytes were indexed."""

    artifact_refs = {
        item.get("schemaRefOrNull")
        for item in evidence_index.get("artifacts", [])
        if isinstance(item, Mapping)
        and isinstance(item.get("schemaRefOrNull"), str)
    }
    artifact_refs.update(
        {
            "contracts/directpath-acceptance-scenario.schema.json",
            "contracts/directpath-execution-evidence-index.schema.json",
            "contracts/directpath-runner-manifest.schema.json",
        }
    )
    return _canonical_string_union(artifact_refs)


def _validate_execution_evidence_index(
    scenario: Mapping[str, Any],
    result: Mapping[str, Any],
    root: Path,
    evidence_git: _GitView | None,
    trust: _TrustContext | None,
    runner_manifest: Mapping[str, Any] | None,
    case_record: Mapping[str, Any] | None,
    fault_classes_by_point: Mapping[str | None, list[str]],
    errors: list[str],
) -> tuple[Mapping[str, Any] | None, dict[str, Mapping[str, Any]]]:
    path = result.get("executionEvidenceIndexPath")
    blob = (
        evidence_git.blob(path, "scenario.executionResult.executionEvidenceIndexPath", errors)
        if evidence_git
        else None
    )
    _check_blob_hash(
        blob,
        result.get("evidenceIndexRecordSha256"),
        "scenario.executionResult ExecutionEvidenceIndex",
        errors,
    )
    index = (
        _load_json_bytes(blob, "ExecutionEvidenceIndex", errors)
        if blob is not None
        else None
    )
    if not isinstance(index, Mapping):
        return None, {}
    _validate_closed_json_schema_instance(
        index,
        root,
        "contracts/directpath-execution-evidence-index.schema.json",
        "ExecutionEvidenceIndex",
        errors,
    )
    _verify_signed_envelope(
        index,
        digest_field="indexDigest",
        signature_field="signature",
        signer_field="signerKeyId",
        signed_time_field="createdAt",
        domain="QMAN-DIRECTPATH/EXECUTION-EVIDENCE-INDEX/V1",
        required_role="TEST_EVIDENCE",
        trust=trust,
        label="ExecutionEvidenceIndex",
        errors=errors,
    )
    if result.get("executionEvidenceIndexDigest") != index.get("indexDigest"):
        errors.append(
            "scenario.executionResult.executionEvidenceIndexDigest: does not equal "
            "signed ExecutionEvidenceIndex.indexDigest"
        )
    target = scenario.get("targetBinding", {})
    exact_fields = {
        "scenarioId": scenario.get("scenarioId"),
        "caseId": scenario.get("caseId"),
        "scenarioRunId": result.get("runId"),
        "targetRepositoryCommit": result.get("targetRepositoryCommit"),
        "mappingCoreId": target.get("mappingCoreId") if isinstance(target, Mapping) else None,
        "portableContractSha256": target.get("portableContractSha256") if isinstance(target, Mapping) else None,
        "caseContractDigest": scenario.get("caseContractDigest"),
        "scenarioInputSha256": result.get("scenarioInputSha256"),
        "runnerManifestDigest": result.get("runnerManifestDigest"),
        "evidenceGrade": result.get("evidenceGrade"),
        "qualificationRunIdOrNull": result.get("qualificationRunIdOrNull"),
        "qualificationRunRequestDigestOrNull": result.get(
            "qualificationRunRequestDigestOrNull"
        ),
        "qualificationRunRequestNonceDigestOrNull": result.get(
            "qualificationRunRequestNonceDigestOrNull"
        ),
        "runStartedAt": result.get("startedAt"),
        "runFinishedAt": result.get("finishedAt"),
    }
    core_digest = _scenario_execution_core_digest(result, errors)
    exact_fields["scenarioExecutionCoreDigest"] = core_digest
    for field, expected in exact_fields.items():
        if index.get(field) != expected:
            errors.append(f"ExecutionEvidenceIndex.{field}: expected {expected!r}")
    requires_hardware = scenario.get("applicability", {}).get(
        "requiresPhysicalHardware"
    ) if isinstance(scenario.get("applicability"), Mapping) else False
    if requires_hardware and index.get("evidenceGrade") != "E4-PHYSICAL-QUALIFICATION":
        errors.append(
            "ExecutionEvidenceIndex.evidenceGrade: physical scenario requires E4"
        )
    elif not requires_hardware and index.get("evidenceGrade") not in {
        "E3-END-TO-END-PRODUCT",
        "E4-PHYSICAL-QUALIFICATION",
    }:
        errors.append("ExecutionEvidenceIndex.evidenceGrade: unsupported grade")
    created = _parse_time(index.get("createdAt"), "ExecutionEvidenceIndex.createdAt", errors)
    run_finished = _parse_time(
        result.get("finishedAt"), "scenario.executionResult.finishedAt", errors
    )
    if created is not None and run_finished is not None and created < run_finished:
        errors.append("ExecutionEvidenceIndex.createdAt: predates run completion")

    decoder_refs = {
        item.get("schemaRef")
        for item in (
            runner_manifest.get("artifactDecoders", [])
            if isinstance(runner_manifest, Mapping)
            else []
        )
        if isinstance(item, Mapping)
        and isinstance(item.get("schemaRef"), str)
    }
    artifacts = index.get("artifacts")
    if not isinstance(artifacts, list):
        artifacts = []
    artifact_by_hash: dict[str, Mapping[str, Any]] = {}
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    order_keys: list[bytes] = []
    for artifact_index, artifact in enumerate(artifacts):
        label = f"ExecutionEvidenceIndex.artifacts[{artifact_index}]"
        if not isinstance(artifact, Mapping):
            continue
        artifact_id = artifact.get("artifactId")
        artifact_path = artifact.get("path")
        digest = artifact.get("sha256")
        if isinstance(artifact_id, str):
            if artifact_id in seen_ids:
                errors.append(f"{label}.artifactId: duplicate identity")
            seen_ids.add(artifact_id)
        if isinstance(artifact_path, str):
            if artifact_path in seen_paths:
                errors.append(f"{label}.path: duplicate artifact path")
            seen_paths.add(artifact_path)
        if isinstance(digest, str):
            if digest in artifact_by_hash:
                errors.append(
                    f"{label}.sha256: one blob cannot satisfy two artifacts"
                )
            artifact_by_hash[digest] = artifact
        try:
            order_keys.append(
                canonical_json_bytes(
                    [
                        artifact.get("iterationRunIdOrNull"),
                        artifact.get("evidenceRole"),
                        artifact_id,
                    ]
                )
            )
        except (CanonicalizationError, TypeError, ValueError) as exc:
            errors.append(f"{label}: invalid order key: {exc}")
        artifact_blob = (
            evidence_git.blob(artifact_path, f"{label}.path", errors)
            if evidence_git
            else None
        )
        _check_blob_hash(artifact_blob, digest, label, errors)
        if artifact_blob is not None and artifact.get("byteLength") != len(artifact_blob):
            errors.append(
                f"{label}.byteLength: declared {artifact.get('byteLength')}, "
                f"actual {len(artifact_blob)}"
            )
        schema_ref = artifact.get("schemaRefOrNull")
        if schema_ref is not None:
            fixed_control_schemas = {
                "contracts/directpath-source-tree-manifest.schema.json",
                "contracts/directpath-build-attestation.schema.json",
            }
            if schema_ref not in decoder_refs and schema_ref not in fixed_control_schemas:
                errors.append(
                    f"{label}.schemaRefOrNull: RunnerManifest has no exact decoder"
                )
            if artifact.get("mediaType") != "application/json":
                errors.append(
                    f"{label}.mediaType: schema-bound artifact must be application/json"
                )
            if artifact_blob is not None and isinstance(schema_ref, str):
                document = _load_json_bytes(artifact_blob, f"{label} typed JSON", errors)
                if document is not None:
                    _validate_closed_json_schema_instance(
                        document, root, schema_ref, f"{label} typed JSON", errors
                    )
    if order_keys != sorted(order_keys):
        errors.append(
            "ExecutionEvidenceIndex.artifacts: must be ordered by canonical "
            "[iterationRunIdOrNull,evidenceRole,artifactId]"
        )

    controls = index.get("requiredControlArtifactHashes")
    control_roles = (
        "sourceTreeManifest",
        "buildAttestation",
        "buildLog",
        "testLog",
        "toolManifest",
        "runnerBinary",
    )
    control_hashes: dict[str, str] = {}
    if isinstance(controls, Mapping):
        for role in control_roles:
            digest = controls.get(role)
            if isinstance(digest, str):
                control_hashes[role] = digest
            else:
                errors.append(
                    f"ExecutionEvidenceIndex control {role}: expected digest string"
                )
    else:
        errors.append(
            "ExecutionEvidenceIndex.requiredControlArtifactHashes: expected object"
        )
    if len(control_hashes) != 6 or len(set(control_hashes.values())) != 6:
        errors.append(
            "ExecutionEvidenceIndex.requiredControlArtifactHashes: six hashes "
            "must be pairwise distinct"
        )
    expected_types = {
        "sourceTreeManifest": "SOURCE_TREE_MANIFEST",
        "buildAttestation": "BUILD_ATTESTATION",
        "buildLog": "BUILD_LOG",
        "testLog": "TEST_LOG",
        "toolManifest": "TOOL_MANIFEST",
        "runnerBinary": "RUNNER_BINARY",
    }
    for role, digest in control_hashes.items():
        artifact = artifact_by_hash.get(digest)
        if artifact is None:
            errors.append(
                f"ExecutionEvidenceIndex control {role}: hash does not resolve an artifact"
            )
            continue
        if artifact.get("artifactType") != expected_types[role]:
            errors.append(
                f"ExecutionEvidenceIndex control {role}: expected artifactType "
                f"{expected_types[role]}"
            )
        if any(
            artifact.get(field) is not None
            for field in (
                "iterationRunIdOrNull",
                "oracleIdOrNull",
                "assertionIdOrNull",
            )
        ):
            errors.append(
                f"ExecutionEvidenceIndex control {role}: must be run-global"
            )
        fixed_control_schema = {
            "sourceTreeManifest": (
                "contracts/directpath-source-tree-manifest.schema.json"
            ),
            "buildAttestation": (
                "contracts/directpath-build-attestation.schema.json"
            ),
        }.get(role)
        if fixed_control_schema is not None:
            if artifact.get("schemaRefOrNull") != fixed_control_schema:
                errors.append(
                    f"ExecutionEvidenceIndex control {role}: schemaRefOrNull must "
                    f"equal {fixed_control_schema!r}"
                )
            if artifact.get("mediaType") != "application/json":
                errors.append(
                    f"ExecutionEvidenceIndex control {role}: expected application/json"
                )
    if isinstance(runner_manifest, Mapping):
        runner = runner_manifest.get("runner", {})
        build = runner_manifest.get("build", {})
        expected_controls = {
            "runnerBinary": runner.get("binaryArtifactSha256") if isinstance(runner, Mapping) else None,
            "sourceTreeManifest": (
                build.get("sourceTreeManifestSha256")
                if isinstance(build, Mapping)
                else None
            ),
            "buildAttestation": (
                build.get("buildAttestation", {}).get("sha256")
                if isinstance(build, Mapping)
                and isinstance(build.get("buildAttestation"), Mapping)
                else None
            ),
            "buildLog": build.get("buildLogArtifactSha256") if isinstance(build, Mapping) else None,
            "toolManifest": build.get("toolManifestArtifactSha256") if isinstance(build, Mapping) else None,
        }
        for role, expected in expected_controls.items():
            if control_hashes.get(role) != expected:
                errors.append(
                    f"ExecutionEvidenceIndex control {role}: RunnerManifest mismatch"
                )
        if isinstance(build, Mapping):
            exclusive_hashes = set(control_hashes.values())
            if len(exclusive_hashes) != 6:
                errors.append(
                    "RunnerManifest build artifacts: six control hashes must be distinct"
                )
            exclusive_paths = {
                artifact_by_hash.get(control_hashes.get(role), {}).get("path")
                for role in control_roles
                if isinstance(control_hashes.get(role), str)
            }
            if len(exclusive_paths) != 6 or None in exclusive_paths:
                errors.append(
                    "RunnerManifest build artifacts: six control paths must be distinct"
                )
            expected_control_paths = {
                "sourceTreeManifest": build.get("sourceTreeManifestPath"),
                "buildAttestation": (
                    build.get("buildAttestation", {}).get("path")
                    if isinstance(build.get("buildAttestation"), Mapping)
                    else None
                ),
            }
            for role, expected_path in expected_control_paths.items():
                artifact = artifact_by_hash.get(control_hashes.get(role))
                if not isinstance(artifact, Mapping) or artifact.get("path") != expected_path:
                    errors.append(
                        f"ExecutionEvidenceIndex control {role}: RunnerManifest path mismatch"
                    )
            build_descriptor = build.get("buildAttestation")
            build_control = artifact_by_hash.get(control_hashes.get("buildAttestation"))
            if isinstance(build_descriptor, Mapping) and isinstance(
                build_control, Mapping
            ):
                for descriptor_field, artifact_field in (
                    ("byteLength", "byteLength"),
                    ("mediaType", "mediaType"),
                    ("schemaRef", "schemaRefOrNull"),
                ):
                    if build_control.get(artifact_field) != build_descriptor.get(
                        descriptor_field
                    ):
                        errors.append(
                            "ExecutionEvidenceIndex control buildAttestation: "
                            f"{artifact_field} descriptor mismatch"
                        )
    if result.get("runnerSha256") != control_hashes.get("runnerBinary"):
        errors.append(
            "scenario.executionResult.runnerSha256: must equal index runnerBinary control"
        )

    scenario_iterations = result.get("iterationResults")
    if not isinstance(scenario_iterations, list):
        scenario_iterations = []
    index_iterations = index.get("iterations")
    if not isinstance(index_iterations, list):
        index_iterations = []
    if len(index_iterations) != len(scenario_iterations):
        errors.append(
            "ExecutionEvidenceIndex.iterations: count must equal scenario result"
        )
    referenced_hash_owner: dict[str, str] = {
        digest: f"CONTROL:{role}"
        for role, digest in control_hashes.items()
        if isinstance(digest, str)
    }
    duration_sum = 0
    previous_finished: _datetime.datetime | None = None
    for iteration_index, index_iteration in enumerate(index_iterations):
        label = f"ExecutionEvidenceIndex.iterations[{iteration_index}]"
        if not isinstance(index_iteration, Mapping):
            continue
        scenario_iteration = (
            scenario_iterations[iteration_index]
            if iteration_index < len(scenario_iterations)
            and isinstance(scenario_iterations[iteration_index], Mapping)
            else {}
        )
        exact_iteration_fields = (
            "iteration",
            "iterationRunId",
            "faultPointOrNull",
            "faultClasses",
            "startedAt",
            "finishedAt",
            "observedDurationSeconds",
            "artifactHashes",
        )
        for field in exact_iteration_fields:
            if index_iteration.get(field) != scenario_iteration.get(field):
                errors.append(f"{label}.{field}: scenario result mismatch")
        point = index_iteration.get("faultPointOrNull")
        if index_iteration.get("faultClasses") != fault_classes_by_point.get(point, []):
            errors.append(f"{label}.faultClasses: fault plan mismatch")
        observed_duration = index_iteration.get("observedDurationSeconds")
        if isinstance(observed_duration, int) and not isinstance(observed_duration, bool):
            duration_sum += observed_duration
        iteration_started = _parse_time(
            index_iteration.get("startedAt"), f"{label}.startedAt", errors
        )
        iteration_finished = _parse_time(
            index_iteration.get("finishedAt"), f"{label}.finishedAt", errors
        )
        if iteration_started is not None and iteration_finished is not None:
            wall_seconds = int((iteration_finished - iteration_started).total_seconds())
            if iteration_started >= iteration_finished:
                errors.append(f"{label}: startedAt must precede finishedAt")
            if isinstance(observed_duration, int) and observed_duration > wall_seconds:
                errors.append(
                    f"{label}.observedDurationSeconds: exceeds floor wall-clock window"
                )
            if previous_finished is not None and iteration_started < previous_finished:
                errors.append(
                    f"{label}.startedAt: iteration observation windows must not overlap"
                )
            previous_finished = iteration_finished
        iteration_run_id = index_iteration.get("iterationRunId")
        actual_iteration_hashes = {
            digest
            for digest, artifact in artifact_by_hash.items()
            if artifact.get("iterationRunIdOrNull") == iteration_run_id
        }
        declared_hash_values = _unique_strings(
            index_iteration.get("artifactHashes"),
            f"{label}.artifactHashes",
            errors,
            nonempty=False,
        )
        declared_hashes = set(declared_hash_values)
        if actual_iteration_hashes != declared_hashes:
            errors.append(
                f"{label}.artifactHashes: must exactly equal same-iteration artifacts"
            )
        if declared_hashes & set(control_hashes.values()):
            errors.append(f"{label}.artifactHashes: control artifacts are run-global")

        expected_oracles: dict[tuple[str, str], list[str]] = {}
        oracle_matrix = scenario_iteration.get("oracleResults")
        if isinstance(oracle_matrix, Mapping):
            for oracle_class in CASE_CONTRACT_ORACLE_CLASSES:
                for oracle in oracle_matrix.get(oracle_class, []):
                    if isinstance(oracle, Mapping) and isinstance(oracle.get("oracleId"), str):
                        expected_oracles[(oracle_class, oracle["oracleId"])] = _unique_strings(
                            oracle.get("evidenceArtifactHashes"),
                            f"{label}.oracleResults.{oracle_class}."
                            f"{oracle['oracleId']}.evidenceArtifactHashes",
                            errors,
                            nonempty=False,
                        )
        actual_oracles: dict[tuple[Any, Any], list[Any]] = {}
        bindings = index_iteration.get("oracleEvidenceBindings")
        if not isinstance(bindings, list):
            bindings = []
        for binding_index, binding in enumerate(bindings):
            binding_label = f"{label}.oracleEvidenceBindings[{binding_index}]"
            if not isinstance(binding, Mapping):
                continue
            oracle_class = binding.get("oracleClass")
            oracle_id = binding.get("oracleId")
            key = (
                (oracle_class, oracle_id)
                if isinstance(oracle_class, str) and isinstance(oracle_id, str)
                else None
            )
            if key is None:
                errors.append(
                    f"{binding_label}: oracleClass/oracleId must be strings"
                )
                continue
            if key in actual_oracles:
                errors.append(f"{binding_label}: duplicate oracle binding")
            hashes = _unique_strings(
                binding.get("artifactHashes"),
                f"{binding_label}.artifactHashes",
                errors,
                nonempty=False,
            )
            actual_oracles[key] = hashes
            _require_canonical_set_order(
                binding.get("artifactHashes"), f"{binding_label}.artifactHashes", errors
            )
            for digest in hashes:
                artifact = artifact_by_hash.get(digest)
                owner = f"ORACLE:{key[0]}:{key[1]}"
                previous_owner = referenced_hash_owner.get(digest)
                if previous_owner is not None and previous_owner != owner:
                    errors.append(
                        f"{binding_label}: evidence {digest!r} is reused by "
                        f"{previous_owner} and {owner}"
                    )
                referenced_hash_owner[digest] = owner
                if artifact is None or artifact.get("iterationRunIdOrNull") != iteration_run_id:
                    errors.append(f"{binding_label}: evidence is not same-iteration")
                elif (
                    artifact.get("oracleIdOrNull") != key[1]
                    or artifact.get("assertionIdOrNull") is not None
                    or artifact.get("evidenceRole") != f"ORACLE:{key[1]}"
                ):
                    errors.append(
                        f"{binding_label}: artifact does not carry exclusive oracle role"
                    )
        if actual_oracles != expected_oracles:
            errors.append(
                f"{label}.oracleEvidenceBindings: must exactly equal scenario oracle matrix"
            )

        expected_predicates: dict[tuple[Any, Any], list[Any]] = {}
        predicate_results = scenario_iteration.get("casePredicateResults")
        if not isinstance(predicate_results, list):
            predicate_results = []
        scenario_predicate_bindings = {
            item.get("assertionId"): item
            for item in scenario.get("casePredicateBindings", [])
            if isinstance(item, Mapping)
            and isinstance(item.get("assertionId"), str)
        }
        for predicate_index, predicate in enumerate(predicate_results):
            predicate_label = f"scenario iteration {iteration_index + 1}.casePredicateResults[{predicate_index}]"
            _exact_keys(
                predicate,
                CASE_PREDICATE_RESULT_FIELDS,
                predicate_label,
                errors,
            )
            if not isinstance(predicate, Mapping):
                continue
            assertion_id = predicate.get("assertionId")
            scenario_binding = (
                scenario_predicate_bindings.get(assertion_id)
                if isinstance(assertion_id, str)
                else None
            )
            if not isinstance(scenario_binding, Mapping):
                errors.append(f"{predicate_label}.assertionId: unknown scenario predicate")
                continue
            if predicate.get("verdict") != "PASS":
                errors.append(f"{predicate_label}.verdict: expected PASS")
            if predicate.get("assertionDigest") != scenario_binding.get("assertionDigest"):
                errors.append(f"{predicate_label}.assertionDigest: scenario mismatch")
            if predicate.get("oracleClass") != scenario_binding.get("oracleClass"):
                errors.append(f"{predicate_label}.oracleClass: scenario mismatch")
            assertion_digest = predicate.get("assertionDigest")
            if isinstance(assertion_id, str) and isinstance(
                assertion_digest, str
            ):
                expected_predicates[(assertion_id, assertion_digest)] = list(
                    _unique_strings(
                        predicate.get("evidenceArtifactHashes"),
                        f"{predicate_label}.evidenceArtifactHashes",
                        errors,
                        nonempty=False,
                    )
                )
            else:
                errors.append(
                    f"{predicate_label}: assertionId/assertionDigest must be strings"
                )
        expected_predicate_ids = list(scenario_predicate_bindings)
        actual_predicate_ids = [
            item.get("assertionId")
            for item in predicate_results
            if isinstance(item, Mapping)
        ]
        if actual_predicate_ids != expected_predicate_ids:
            errors.append(
                f"{label}: casePredicateResults must exactly cover every scenario assertion"
            )

        actual_predicates: dict[tuple[Any, Any], list[Any]] = {}
        predicate_bindings = index_iteration.get("predicateEvidenceBindings")
        if not isinstance(predicate_bindings, list):
            predicate_bindings = []
        for binding_index, binding in enumerate(predicate_bindings):
            binding_label = f"{label}.predicateEvidenceBindings[{binding_index}]"
            if not isinstance(binding, Mapping):
                continue
            assertion_id = binding.get("assertionId")
            assertion_digest = binding.get("assertionDigest")
            key = (
                (assertion_id, assertion_digest)
                if isinstance(assertion_id, str)
                and isinstance(assertion_digest, str)
                else None
            )
            if key is None:
                errors.append(
                    f"{binding_label}: assertionId/assertionDigest must be strings"
                )
                continue
            if key in actual_predicates:
                errors.append(f"{binding_label}: duplicate predicate binding")
            hashes = _unique_strings(
                binding.get("artifactHashes"),
                f"{binding_label}.artifactHashes",
                errors,
                nonempty=False,
            )
            actual_predicates[key] = hashes
            _require_canonical_set_order(
                binding.get("artifactHashes"), f"{binding_label}.artifactHashes", errors
            )
            for digest in hashes:
                artifact = artifact_by_hash.get(digest)
                owner = f"PREDICATE:{key[0]}"
                previous_owner = referenced_hash_owner.get(digest)
                if previous_owner is not None and previous_owner != owner:
                    errors.append(
                        f"{binding_label}: evidence {digest!r} is reused by "
                        f"{previous_owner} and {owner}"
                    )
                referenced_hash_owner[digest] = owner
                if artifact is None or artifact.get("iterationRunIdOrNull") != iteration_run_id:
                    errors.append(f"{binding_label}: evidence is not same-iteration")
                elif (
                    artifact.get("assertionIdOrNull") != key[0]
                    or artifact.get("oracleIdOrNull") is not None
                    or artifact.get("evidenceRole") != f"PREDICATE:{key[0]}"
                ):
                    errors.append(
                        f"{binding_label}: artifact does not carry exclusive predicate role"
                    )
        if actual_predicates != expected_predicates:
            errors.append(
                f"{label}.predicateEvidenceBindings: must exactly equal scenario "
                "predicate results"
            )

        special_artifacts = {
            "scheduleTraceArtifactHash": "SCHEDULE_TRACE",
            "cleanupProofArtifactHash": "CLEANUP_PROOF",
        }
        direct_special_hashes: set[str] = set()
        for field, artifact_type in special_artifacts.items():
            digest = scenario_iteration.get(field)
            artifact = artifact_by_hash.get(digest) if isinstance(digest, str) else None
            if isinstance(digest, str):
                direct_special_hashes.add(digest)
            if artifact is None or artifact.get("artifactType") != artifact_type:
                errors.append(f"{label}: {field} must resolve {artifact_type}")
        barrier_hashes = _unique_strings(
            scenario_iteration.get("barrierObservationArtifactHashes"),
            f"{label}.barrierObservationArtifactHashes",
            errors,
            nonempty=False,
        )
        for digest in barrier_hashes:
            direct_special_hashes.add(digest)
            artifact = artifact_by_hash.get(digest)
            if artifact is None or artifact.get("artifactType") != "BARRIER_OBSERVATION":
                errors.append(
                    f"{label}: barrier hash must resolve BARRIER_OBSERVATION"
                )
        bound_hashes = {
            digest
            for digest, owner in referenced_hash_owner.items()
            if owner.startswith(("ORACLE:", "PREDICATE:"))
            and digest in declared_hashes
        }
        if bound_hashes | direct_special_hashes != declared_hashes:
            errors.append(
                f"{label}.artifactHashes: every iteration artifact must have exactly "
                "one oracle, predicate, schedule, barrier, or cleanup role"
            )
    top_duration = index.get("observedDurationSeconds")
    if top_duration != duration_sum:
        errors.append(
            "ExecutionEvidenceIndex.observedDurationSeconds: must equal exact sum "
            f"of iteration durations {duration_sum}"
        )
    index_started = _parse_time(index.get("runStartedAt"), "ExecutionEvidenceIndex.runStartedAt", errors)
    index_finished = _parse_time(index.get("runFinishedAt"), "ExecutionEvidenceIndex.runFinishedAt", errors)
    if index_started is not None and index_finished is not None:
        wall_seconds = int((index_finished - index_started).total_seconds())
        if index_started >= index_finished:
            errors.append("ExecutionEvidenceIndex: runStartedAt must precede runFinishedAt")
        if isinstance(top_duration, int) and top_duration > wall_seconds:
            errors.append(
                "ExecutionEvidenceIndex.observedDurationSeconds: exceeds floor "
                "aggregate wall-clock window"
            )
    if isinstance(case_record, Mapping):
        minimum_duration = case_record.get("minimumDurationSeconds")
        if (
            isinstance(minimum_duration, int)
            and isinstance(top_duration, int)
            and top_duration < minimum_duration
        ):
            errors.append(
                "ExecutionEvidenceIndex.observedDurationSeconds: below Case minimum "
                f"{minimum_duration}"
            )

    global_noncontrols = {
        digest
        for digest, artifact in artifact_by_hash.items()
        if artifact.get("iterationRunIdOrNull") is None
        and digest not in set(control_hashes.values())
    }
    qualification_subject_hashes: set[str] = set()
    for digest in global_noncontrols:
        artifact = artifact_by_hash[digest]
        if artifact.get("artifactType") == "QUALIFICATION_SUBJECT":
            qualification_subject_hashes.add(digest)
            if artifact.get("schemaRefOrNull") != (
                "contracts/directpath-qualification-subject-manifest.schema.json"
            ):
                errors.append(
                    "ExecutionEvidenceIndex QUALIFICATION_SUBJECT: expected exact "
                    "normative subject schema"
                )
            if artifact.get("evidenceRole") != "QUALIFICATION_SUBJECT":
                errors.append(
                    "ExecutionEvidenceIndex QUALIFICATION_SUBJECT: expected exclusive "
                    "evidenceRole QUALIFICATION_SUBJECT"
                )
            if artifact.get("oracleIdOrNull") is not None or artifact.get(
                "assertionIdOrNull"
            ) is not None:
                errors.append(
                    "ExecutionEvidenceIndex QUALIFICATION_SUBJECT: oracle/assertion "
                    "bindings are forbidden"
                )
        elif artifact.get("artifactType") == "TYPED_ENTITY" and (
            artifact.get("evidenceRole") == "INVENTORY_SNAPSHOT"
            or str(artifact.get("evidenceRole", "")).startswith("MEASUREMENT:")
        ):
            if artifact.get("oracleIdOrNull") is not None or artifact.get(
                "assertionIdOrNull"
            ) is not None:
                errors.append(
                    "ExecutionEvidenceIndex measurement artifact: oracle/assertion "
                    "bindings are forbidden"
                )
        else:
            errors.append(
                "ExecutionEvidenceIndex.artifacts: non-control run-global artifacts "
                "must be QUALIFICATION_SUBJECT or typed measurement evidence"
            )
    if index.get("evidenceGrade") == "E4-PHYSICAL-QUALIFICATION":
        if len(qualification_subject_hashes) != 1:
            errors.append(
                "ExecutionEvidenceIndex E4: exactly one run-global "
                "QUALIFICATION_SUBJECT artifact is required"
            )
    elif qualification_subject_hashes:
        errors.append(
            "ExecutionEvidenceIndex E3: QUALIFICATION_SUBJECT artifact is forbidden"
        )
    return index, artifact_by_hash


def _validate_operation_exchanges(
    *,
    scenario: Mapping[str, Any],
    iteration: Mapping[str, Any],
    contract: Mapping[str, Any],
    root: Path,
    evidence_git: _GitView | None,
    correlated_instances: list[tuple[Mapping[str, Any], bytes | None]],
    instance_subject_bindings: Mapping[int, dict[str, str]],
    iteration_started: _datetime.datetime | None,
    iteration_finished: _datetime.datetime | None,
    seen_envelope_paths: set[str],
    seen_envelope_hashes: set[str],
    errors: list[str],
    label: str,
) -> None:
    """Prove one ordered Step -> raw REQUEST/RESULT envelope bijection."""

    steps = scenario.get("steps")
    if not isinstance(steps, list):
        errors.append(f"{label}: scenario steps are unavailable")
        return
    exchanges = iteration.get("operationExchanges")
    if not isinstance(exchanges, list):
        errors.append(f"{label}.operationExchanges: expected array")
        return
    if len(exchanges) != len(steps):
        errors.append(
            f"{label}.operationExchanges: expected exact {len(steps)}-step "
            f"bijection, found {len(exchanges)}"
        )
    operation_instance_types = {
        "operation-request-envelope",
        "operation-result-envelope",
    }
    operation_instances = [
        pair
        for pair in correlated_instances
        if pair[0].get("artifactType") in operation_instance_types
    ]
    claimed_instance_ids: set[int] = set()
    target = scenario.get("targetBinding")
    target_commit = _normal_commit(
        target.get("repositoryCommit") if isinstance(target, Mapping) else None,
        f"{label}.targetBinding.repositoryCommit",
        errors,
    )
    expected_object_format = (
        "SHA1" if isinstance(target_commit, str) and len(target_commit) == 40 else "SHA256"
    )
    target_portable_hash = (
        target.get("portableContractSha256") if isinstance(target, Mapping) else None
    )
    common_envelope_fields = (
        "operationId",
        "commandId",
        "idempotencyMode",
        "idempotencyKey",
        "actorPortId",
        "portableContractId",
        "portableContractRevision",
        "portableContractSha256",
        "targetRepositoryObjectFormat",
        "targetRepositoryCommit",
        "payloadSchemaAuthority",
        "payloadSchemaSha256",
        "payloadCanonicalProfile",
        "correlation",
    )

    for number, exchange in enumerate(exchanges):
        exchange_label = f"{label}.operationExchanges[{number}]"
        _exact_keys(exchange, OPERATION_EXCHANGE_FIELDS, exchange_label, errors)
        if not isinstance(exchange, Mapping):
            continue
        if number >= len(steps) or not isinstance(steps[number], Mapping):
            continue
        step = steps[number]
        sequence = number + 1
        operation_id = step.get("operationId")
        if exchange.get("stepSequence") != sequence:
            errors.append(f"{exchange_label}.stepSequence: expected {sequence}")
        if exchange.get("operationId") != operation_id:
            errors.append(f"{exchange_label}.operationId: scenario Step mismatch")

        envelopes: dict[str, Mapping[str, Any]] = {}
        envelope_blobs: dict[str, bytes] = {}
        descriptors: dict[str, Mapping[str, Any]] = {}
        for direction, descriptor_field, schema_fragment, descriptor_fields in (
            (
                "REQUEST",
                "requestEnvelope",
                "contracts/directpath-operation-envelope.schema.json"
                "#/$defs/requestEnvelope",
                OPERATION_REQUEST_ENVELOPE_ARTIFACT_FIELDS,
            ),
            (
                "RESULT",
                "resultEnvelope",
                "contracts/directpath-operation-envelope.schema.json"
                "#/$defs/resultEnvelope",
                OPERATION_RESULT_ENVELOPE_ARTIFACT_FIELDS,
            ),
        ):
            descriptor = exchange.get(descriptor_field)
            descriptor_label = f"{exchange_label}.{descriptor_field}"
            _exact_keys(descriptor, descriptor_fields, descriptor_label, errors)
            if not isinstance(descriptor, Mapping):
                continue
            descriptors[direction] = descriptor
            blob, envelope = _resolve_pinned_json_descriptor(
                descriptor,
                expected_schema_ref=schema_fragment,
                evidence_git=evidence_git,
                root=root,
                label=descriptor_label,
                errors=errors,
            )
            if blob is not None:
                envelope_blobs[direction] = blob
            if not isinstance(envelope, Mapping):
                continue
            envelopes[direction] = envelope
            expected_kind = direction
            if envelope.get("envelopeKind") != expected_kind:
                errors.append(f"{descriptor_label}.envelopeKind: expected {expected_kind}")
            if envelope.get("operationId") != operation_id:
                errors.append(f"{descriptor_label}.operationId: scenario Step mismatch")
            if descriptor.get("payloadHash") != envelope.get("payloadHash"):
                errors.append(f"{descriptor_label}.payloadHash: parsed envelope mismatch")
            internal_hash_field = "requestHash" if direction == "REQUEST" else "resultHash"
            projection = copy.deepcopy(dict(envelope))
            projection[internal_hash_field] = None
            actual_internal_hash = _canonical_digest(
                projection, f"{descriptor_label}.{internal_hash_field} projection", errors
            )
            if envelope.get(internal_hash_field) != actual_internal_hash:
                errors.append(
                    f"{descriptor_label}.{internal_hash_field}: canonical projection mismatch"
                )
            if descriptor.get("envelopeHash") != envelope.get(internal_hash_field):
                errors.append(f"{descriptor_label}.envelopeHash: parsed envelope mismatch")
            for digest in (descriptor.get("sha256"), descriptor.get("envelopeHash")):
                if isinstance(digest, str):
                    if digest in seen_envelope_hashes:
                        errors.append(
                            f"{descriptor_label}: envelope/raw hash is reused across "
                            "steps or iterations"
                        )
                    seen_envelope_hashes.add(digest)
            descriptor_path = descriptor.get("path")
            if isinstance(descriptor_path, str):
                if descriptor_path in seen_envelope_paths:
                    errors.append(
                        f"{descriptor_label}.path: envelope path is reused across "
                        "steps or iterations"
                    )
                seen_envelope_paths.add(descriptor_path)

            artifact_type = (
                "operation-request-envelope"
                if direction == "REQUEST"
                else "operation-result-envelope"
            )
            matches = [
                pair
                for pair in operation_instances
                if pair[0].get("artifactType") == artifact_type
                and pair[0].get("producer") == "MAPPED-OPERATION-ACTOR"
                and pair[0].get("path") == descriptor.get("path")
                and pair[0].get("sha256") == descriptor.get("sha256")
            ]
            if len(matches) != 1:
                errors.append(
                    f"{descriptor_label}: expected exactly one same-iteration "
                    f"MAPPED-OPERATION-ACTOR ArtifactInstance, found {len(matches)}"
                )
            else:
                instance, instance_blob = matches[0]
                claimed_instance_ids.add(id(instance))
                if blob is not None and instance_blob != blob:
                    errors.append(f"{descriptor_label}: ArtifactInstance raw bytes mismatch")
                correlation = instance.get("correlation")
                bindings = instance_subject_bindings.get(id(instance), {})
                expected_bindings = {
                    "operationId": str(operation_id),
                    "payloadHash": str(envelope.get("payloadHash")),
                    internal_hash_field: str(envelope.get(internal_hash_field)),
                    "stepSequence": str(sequence),
                }
                if bindings != expected_bindings:
                    errors.append(
                        f"{descriptor_label}: ArtifactInstance subjectBindings must "
                        "exactly bind operation/payload/envelope hash/step"
                    )
                if isinstance(correlation, Mapping):
                    if correlation.get("commandIdOrNull") != envelope.get("commandId"):
                        errors.append(
                            f"{descriptor_label}: ArtifactInstance commandId mismatch"
                        )
                    raw_correlation = envelope.get("correlation")
                    if isinstance(raw_correlation, Mapping):
                        for instance_field, raw_field in (
                            ("assignmentIdOrNull", "assignmentIdOrNull"),
                            ("runIdOrNull", "runIdOrNull"),
                        ):
                            if correlation.get(instance_field) != raw_correlation.get(raw_field):
                                errors.append(
                                    f"{descriptor_label}: ArtifactInstance {instance_field} "
                                    "does not bind the raw envelope"
                                )

        request_envelope = envelopes.get("REQUEST")
        result_envelope = envelopes.get("RESULT")
        request_descriptor = descriptors.get("REQUEST")
        result_descriptor = descriptors.get("RESULT")
        if not all(
            isinstance(item, Mapping)
            for item in (
                request_envelope,
                result_envelope,
                request_descriptor,
                result_descriptor,
            )
        ):
            continue
        assert request_envelope is not None
        assert result_envelope is not None
        assert request_descriptor is not None
        assert result_descriptor is not None
        if request_descriptor.get("path") == result_descriptor.get("path") or request_descriptor.get(
            "sha256"
        ) == result_descriptor.get("sha256"):
            errors.append(f"{exchange_label}: REQUEST and RESULT raw identities must differ")
        for field in common_envelope_fields:
            if request_envelope.get(field) != result_envelope.get(field):
                errors.append(f"{exchange_label}: REQUEST/RESULT {field} mismatch")
        fixed_common = {
            "portableContractId": contract.get("contractId"),
            "portableContractRevision": contract.get("revision"),
            "portableContractSha256": target_portable_hash,
            "targetRepositoryObjectFormat": expected_object_format,
            "targetRepositoryCommit": target_commit,
        }
        for field, expected in fixed_common.items():
            if request_envelope.get(field) != expected:
                errors.append(f"{exchange_label}.requestEnvelope.{field}: target mismatch")

        request_binding = step.get("request")
        result_binding = step.get("expectedImmediateResult")
        for direction, envelope, descriptor, binding in (
            ("REQUEST", request_envelope, request_descriptor, request_binding),
            ("RESULT", result_envelope, result_descriptor, result_binding),
        ):
            if not isinstance(binding, Mapping):
                errors.append(f"{exchange_label}.{direction}: Step payload binding unavailable")
                continue
            for field in (
                "operationId",
                "payloadSchemaAuthority",
                "payloadSchemaRef",
                "payloadSchemaSha256",
                "payloadCanonicalProfile",
            ):
                if envelope.get(field) != binding.get(field):
                    errors.append(
                        f"{exchange_label}.{direction}.{field}: detached fixture mismatch"
                    )
            if envelope.get("payloadHash") != binding.get("payloadHashOrNull"):
                errors.append(
                    f"{exchange_label}.{direction}.payloadHash: detached fixture mismatch"
                )
            if descriptor.get("payloadHash") != binding.get("payloadHashOrNull"):
                errors.append(
                    f"{exchange_label}.{direction}.descriptor.payloadHash: fixture mismatch"
                )

        reason = result_envelope.get("reason")
        reason_code = reason.get("code") if isinstance(reason, Mapping) else None
        result_projection = {
            "status": result_envelope.get("status"),
            "reasonCodeOrNull": reason_code,
            "retryable": result_envelope.get("retryable"),
        }
        expected_projection = {
            "status": result_binding.get("expectedStatus")
            if isinstance(result_binding, Mapping)
            else None,
            "reasonCodeOrNull": result_binding.get("expectedReasonCodeOrNull")
            if isinstance(result_binding, Mapping)
            else None,
            "retryable": result_binding.get("expectedRetryable")
            if isinstance(result_binding, Mapping)
            else None,
        }
        if result_projection != expected_projection:
            errors.append(
                f"{exchange_label}.resultEnvelope: status/reason/retryable does not "
                "project the Step expectedImmediateResult"
            )
        for field, expected in result_projection.items():
            if result_descriptor.get(field) != expected:
                errors.append(f"{exchange_label}.resultEnvelope.{field}: descriptor mismatch")

        issued = _parse_time(
            request_envelope.get("issuedAt"), f"{exchange_label}.issuedAt", errors
        )
        deadline = _parse_time(
            request_envelope.get("deadlineAt"), f"{exchange_label}.deadlineAt", errors
        )
        completed = _parse_time(
            result_envelope.get("completedAt"), f"{exchange_label}.completedAt", errors
        )
        if issued is not None and deadline is not None and issued >= deadline:
            errors.append(f"{exchange_label}: issuedAt must precede deadlineAt")
        if issued is not None and completed is not None and completed < issued:
            errors.append(f"{exchange_label}: completedAt predates issuedAt")
        if deadline is not None and completed is not None and completed > deadline:
            errors.append(f"{exchange_label}: completedAt exceeds request deadlineAt")
        if iteration_started is not None and issued is not None and issued < iteration_started:
            errors.append(f"{exchange_label}.issuedAt: predates iteration window")
        if iteration_finished is not None and completed is not None and completed > iteration_finished:
            errors.append(f"{exchange_label}.completedAt: follows iteration window")

    if claimed_instance_ids != {id(instance) for instance, _ in operation_instances}:
        errors.append(
            f"{label}.operationExchanges: must claim all and only same-iteration "
            "operation envelope ArtifactInstances"
        )


def _validate_execution_result(
    scenario: Mapping[str, Any],
    result: Any,
    contract: Mapping[str, Any],
    evidence_git: _GitView | None,
    trust: _TrustContext | None,
    repeat: int | None,
    fault_plan_counts: Mapping[str | None, int],
    fault_classes_by_point: Mapping[str | None, list[str]] | list[Any],
    artifact_expectations: list[Any] | list[str],
    errors: list[str] | None = None,
    *,
    root: Path | None = None,
    code_git: _GitView | None = None,
    mapping: Mapping[str, Any] | None = None,
    case_registry: Mapping[str, Any] | None = None,
    case_record: Mapping[str, Any] | None = None,
) -> None:
    # Compatibility with the original helper API, whose positional tail was
    # ``fault_plan_counts, artifact_expectations, errors``.  Keeping this path
    # matters to external/offline conformance suites that import the validator
    # as a module rather than invoking only its CLI.
    if errors is None and not isinstance(fault_classes_by_point, Mapping):
        errors = artifact_expectations  # type: ignore[assignment]
        artifact_expectations = fault_classes_by_point
        fault_classes_by_point = {None: []}
    if errors is None:
        raise TypeError("_validate_execution_result() requires an errors list")
    if root is None:
        root = Path.cwd()
    _exact_keys(result, EXECUTION_RESULT_FIELDS, "scenario.executionResult", errors)
    if not isinstance(result, Mapping):
        return
    if result.get("verdict") != "PASS":
        errors.append("scenario.executionResult.verdict: only PASS is eligible")
    if result.get("resultCanonicalization") != "CANONICAL-JSON-V1":
        errors.append("scenario.executionResult.resultCanonicalization: unsupported profile")
    limitations = result.get("limitations")
    _unique_strings(limitations, "scenario.executionResult.limitations", errors, nonempty=False)
    if limitations:
        errors.append(
            "scenario.executionResult.limitations: a limited PASS cannot close a Case/status/qualification"
        )
    target = scenario.get("targetBinding", {})
    result_commit = _normal_commit(
        result.get("targetRepositoryCommit"), "scenario.executionResult.targetRepositoryCommit", errors
    )
    target_commit = _normal_commit(
        target.get("repositoryCommit"), "scenario.targetBinding.repositoryCommit", errors
    )
    if result_commit != target_commit:
        errors.append("scenario.executionResult.targetRepositoryCommit: does not match target binding")
    correlation_fields = (
        "evidenceGrade",
        "qualificationRunIdOrNull",
        "qualificationRunRequestDigestOrNull",
        "qualificationRunRequestNonceDigestOrNull",
    )
    if not isinstance(target, Mapping) or any(
        result.get(field) != target.get(field) for field in correlation_fields
    ):
        errors.append(
            "scenario.executionResult: evidence grade and qualification-run "
            "correlation must byte-equal targetBinding"
        )
    scenario_projection = copy.deepcopy(dict(scenario))
    scenario_projection["executionResult"] = None
    input_digest = _canonical_digest(scenario_projection, "scenario input projection", errors)
    if input_digest is not None and result.get("scenarioInputSha256") != input_digest:
        errors.append(
            f"scenario.executionResult.scenarioInputSha256: declared {result.get('scenarioInputSha256')}, actual {input_digest}"
        )
    started = _parse_time(result.get("startedAt"), "scenario.executionResult.startedAt", errors)
    finished = _parse_time(result.get("finishedAt"), "scenario.executionResult.finishedAt", errors)
    if started is not None and finished is not None and started >= finished:
        errors.append("scenario.executionResult: startedAt must precede finishedAt")
    runner_manifest = _validate_runner_manifest(
        scenario,
        result,
        root,
        code_git,
        evidence_git,
        mapping,
        trust,
        case_registry,
        case_record,
        errors,
    )
    _evidence_index, index_artifacts = _validate_execution_evidence_index(
        scenario,
        result,
        root,
        evidence_git,
        trust,
        runner_manifest,
        case_record,
        fault_classes_by_point,
        errors,
    )
    instances = result.get("artifactInstances")
    if not isinstance(instances, list) or not instances:
        errors.append("scenario.executionResult.artifactInstances: expected non-empty array")
        instances = []
    artifact_hashes: set[str] = set()
    instance_records: list[tuple[Mapping[str, Any], bytes | None]] = []
    instance_subject_bindings: dict[int, dict[str, str]] = {}
    for index, instance in enumerate(instances):
        label = f"scenario.executionResult.artifactInstances[{index}]"
        _exact_keys(instance, ARTIFACT_INSTANCE_FIELDS, label, errors)
        if not isinstance(instance, Mapping):
            continue
        if instance.get("artifactType") in {
            "RUNNER_MANIFEST",
            "EXECUTION_EVIDENCE_INDEX",
            "QUALIFICATION_SUBJECT",
        }:
            errors.append(
                f"{label}.artifactType: run-global/self artifact is forbidden from "
                "iteration-scoped artifactInstances"
            )
        blob = (
            evidence_git.blob(instance.get("path"), f"{label}.path", errors)
            if evidence_git
            else None
        )
        _check_blob_hash(blob, instance.get("sha256"), label, errors)
        digest = instance.get("sha256")
        if isinstance(digest, str):
            if digest in artifact_hashes:
                errors.append(f"{label}.sha256: duplicate artifact instance hash")
            artifact_hashes.add(digest)
        correlation = instance.get("correlation")
        _exact_keys(correlation, ARTIFACT_CORRELATION_FIELDS, f"{label}.correlation", errors)
        if isinstance(correlation, Mapping):
            if correlation.get("scenarioId") != scenario.get("scenarioId"):
                errors.append(
                    f"{label}.correlation.scenarioId: must equal scenario.scenarioId"
                )
            if correlation.get("caseId") != scenario.get("caseId"):
                errors.append(
                    f"{label}.correlation.caseId: must equal scenario.caseId"
                )
            if correlation.get("scenarioRunId") != result.get("runId"):
                errors.append(
                    f"{label}.correlation.scenarioRunId: must equal executionResult.runId"
                )
            iteration_number = correlation.get("iteration")
            if (
                not isinstance(iteration_number, int)
                or isinstance(iteration_number, bool)
                or iteration_number < 1
            ):
                errors.append(f"{label}.correlation.iteration: expected positive integer")
            if (
                not isinstance(correlation.get("iterationRunId"), str)
                or not correlation.get("iterationRunId")
            ):
                errors.append(
                    f"{label}.correlation.iterationRunId: expected non-empty string"
                )
            point = correlation.get("faultPointOrNull")
            if point is not None and (not isinstance(point, str) or not point):
                errors.append(
                    f"{label}.correlation.faultPointOrNull: expected null or non-empty string"
                )
            for field in ("commandIdOrNull", "assignmentIdOrNull", "runIdOrNull"):
                value = correlation.get(field)
                if value is not None and (not isinstance(value, str) or not value):
                    errors.append(
                        f"{label}.correlation.{field}: expected null or non-empty string"
                    )
            instance_subject_bindings[id(instance)] = _subject_binding_map(
                correlation.get("subjectBindings"),
                f"{label}.correlation.subjectBindings",
                errors,
            )
        instance_records.append((instance, blob))
    for field in (
        "runnerSha256",
        "runnerManifestDigest",
        "evidenceIndexRecordSha256",
        "executionEvidenceIndexDigest",
    ):
        _is_digest(result.get(field), f"scenario.executionResult.{field}", errors, nonzero=True)
    if result.get("runnerSha256") == result.get("evidenceIndexRecordSha256"):
        errors.append(
            "scenario.executionResult: runner binary and EvidenceIndex raw bytes "
            "must be distinct"
        )
    iterations = result.get("iterationResults")
    if not isinstance(iterations, list):
        errors.append("scenario.executionResult.iterationResults: expected array")
        iterations = []
    if repeat is not None and len(iterations) != repeat:
        errors.append(
            f"scenario.executionResult.iterationResults: expected exactly {repeat}, found {len(iterations)}"
        )
    expected_ids = _expected_oracle_ids(scenario)
    seen_iteration_runs: set[str] = set()
    observed_fault_counts: dict[str | None, int] = {}
    hashes_bound_to_valid_iterations: set[str] = set()
    seen_operation_envelope_paths: set[str] = set()
    seen_operation_envelope_hashes: set[str] = set()
    for index, iteration in enumerate(iterations):
        label = f"scenario.executionResult.iterationResults[{index}]"
        _exact_keys(iteration, ITERATION_FIELDS, label, errors)
        if not isinstance(iteration, Mapping):
            continue
        iteration_number = iteration.get("iteration")
        if iteration_number != index + 1:
            errors.append(f"{label}.iteration: expected {index + 1}")
        iteration_run_id = iteration.get("iterationRunId")
        if not isinstance(iteration_run_id, str) or not iteration_run_id:
            errors.append(f"{label}.iterationRunId: expected non-empty string")
        elif iteration_run_id in seen_iteration_runs:
            errors.append(f"{label}.iterationRunId: duplicate iteration run identity")
        else:
            seen_iteration_runs.add(iteration_run_id)
        if iteration.get("verdict") != "PASS":
            errors.append(f"{label}.verdict: expected PASS")
        point = iteration.get("faultPointOrNull")
        iteration_fault_classes = _unique_strings(
            iteration.get("faultClasses"), f"{label}.faultClasses", errors
        )
        _require_canonical_set_order(
            iteration.get("faultClasses"), f"{label}.faultClasses", errors
        )
        if iteration_fault_classes != fault_classes_by_point.get(point, []):
            errors.append(f"{label}.faultClasses: exact fault-plan mismatch")
        if point not in fault_plan_counts:
            errors.append(
                f"{label}.faultPointOrNull: {point!r} is absent from the exact fault-point plan"
            )
        else:
            observed_fault_counts[point] = observed_fault_counts.get(point, 0) + 1
        iteration_started = _parse_time(iteration.get("startedAt"), f"{label}.startedAt", errors)
        iteration_finished = _parse_time(iteration.get("finishedAt"), f"{label}.finishedAt", errors)
        if iteration_started is not None and iteration_finished is not None:
            if iteration_started >= iteration_finished:
                errors.append(f"{label}: startedAt must precede finishedAt")
            if started is not None and iteration_started < started:
                errors.append(f"{label}.startedAt: precedes aggregate execution start")
            if finished is not None and iteration_finished > finished:
                errors.append(f"{label}.finishedAt: follows aggregate execution finish")
            duration = iteration.get("observedDurationSeconds")
            wall_seconds = int((iteration_finished - iteration_started).total_seconds())
            if (
                not isinstance(duration, int)
                or isinstance(duration, bool)
                or duration < 1
                or duration > wall_seconds
            ):
                errors.append(
                    f"{label}.observedDurationSeconds: expected positive monotonic "
                    "duration no greater than floor wall-clock window"
                )

        correlated_instances: list[tuple[Mapping[str, Any], bytes | None]] = []
        for instance, blob in instance_records:
            correlation = instance.get("correlation")
            if not isinstance(correlation, Mapping):
                continue
            if (
                correlation.get("scenarioRunId") == result.get("runId")
                and correlation.get("iterationRunId") == iteration_run_id
                and correlation.get("iteration") == iteration_number
                and correlation.get("faultPointOrNull") == point
            ):
                correlated_instances.append((instance, blob))
        correlated_hashes = {
            instance.get("sha256")
            for instance, _ in correlated_instances
            if isinstance(instance.get("sha256"), str)
        }
        hashes_bound_to_valid_iterations.update(correlated_hashes)
        declared_artifact_hashes = _unique_strings(
            iteration.get("artifactHashes"), f"{label}.artifactHashes", errors
        )
        _require_canonical_set_order(
            iteration.get("artifactHashes"), f"{label}.artifactHashes", errors
        )
        for digest in declared_artifact_hashes:
            _is_digest(digest, f"{label}.artifactHashes", errors, nonzero=True)
        if set(declared_artifact_hashes) != correlated_hashes:
            errors.append(
                f"{label}.artifactHashes: must exactly equal all and only artifact "
                "instances correlated to this iteration"
            )

        _validate_operation_exchanges(
            scenario=scenario,
            iteration=iteration,
            contract=contract,
            root=root,
            evidence_git=evidence_git,
            correlated_instances=correlated_instances,
            instance_subject_bindings=instance_subject_bindings,
            iteration_started=iteration_started,
            iteration_finished=iteration_finished,
            seen_envelope_paths=seen_operation_envelope_paths,
            seen_envelope_hashes=seen_operation_envelope_hashes,
            errors=errors,
            label=label,
        )

        clean_receipts: dict[
            str, tuple[Mapping[str, Any], Mapping[str, Any]]
        ] = {}
        clean_acceptances: dict[
            str, tuple[Mapping[str, Any], Mapping[str, Any]]
        ] = {}
        for expectation_index, expectation in enumerate(artifact_expectations):
            if not isinstance(expectation, Mapping):
                continue
            matches = [
                pair
                for pair in correlated_instances
                if pair[0].get("artifactType") == expectation.get("artifactType")
                and pair[0].get("producer") == expectation.get("producer")
            ]
            if not matches:
                errors.append(
                    f"{label}: scenario.artifacts[{expectation_index}] has no "
                    "producer/type instance for this exact iteration"
                )
                continue
            required_correlation = set(expectation.get("correlationFields", []))
            if not any(
                isinstance(instance.get("correlation"), Mapping)
                and all(
                    _correlation_field_resolves_once(
                        instance["correlation"],
                        instance_subject_bindings.get(id(instance), {}),
                        field,
                    )
                    for field in required_correlation
                )
                for instance, _ in matches
            ):
                errors.append(
                    f"{label}: scenario.artifacts[{expectation_index}] lacks every "
                    "required uniquely resolved correlation value"
                )
            if expectation.get("formatOrSchema") == "ENTITY-CLEAN-RELEASE-RECEIPT":
                for instance, blob in matches:
                    if blob is None:
                        continue
                    receipt = _load_json_bytes(
                        blob,
                        f"{label} clean release receipt artifact",
                        errors,
                    )
                    _validate_clean_release_receipt(
                        receipt,
                        contract,
                        trust,
                        f"clean release receipt artifact {instance.get('path')}",
                        errors,
                        correlation=(
                            instance.get("correlation")
                            if isinstance(instance.get("correlation"), Mapping)
                            else None
                        ),
                        subject_bindings=instance_subject_bindings.get(id(instance)),
                        iteration_finished=iteration_finished,
                    )
                    if isinstance(receipt, Mapping) and isinstance(
                        instance.get("sha256"), str
                    ):
                        clean_receipts[instance["sha256"]] = (receipt, instance)
            if expectation.get("formatOrSchema") == "ENTITY-CLEAN-RELEASE-ACCEPTANCE":
                for instance, blob in matches:
                    if blob is None:
                        continue
                    acceptance = _load_json_bytes(
                        blob,
                        f"{label} clean release acceptance artifact",
                        errors,
                    )
                    if isinstance(acceptance, Mapping) and isinstance(
                        instance.get("sha256"), str
                    ):
                        clean_acceptances[instance["sha256"]] = (
                            acceptance,
                            instance,
                        )

        acceptance_receipt_digests: dict[str, list[tuple[Mapping[str, Any], Mapping[str, Any]]]] = {}
        for acceptance, instance in clean_acceptances.values():
            receipt_digest = acceptance.get("receiptDigest")
            if not isinstance(receipt_digest, str):
                _is_digest(
                    receipt_digest,
                    f"clean release acceptance artifact {instance.get('path')}.receiptDigest",
                    errors,
                    nonzero=True,
                )
                continue
            acceptance_receipt_digests.setdefault(receipt_digest, []).append(
                (acceptance, instance)
            )
        matched_acceptance_hashes: set[str] = set()
        for receipt, receipt_instance in clean_receipts.values():
            receipt_digest = receipt.get("receiptDigest")
            matches = acceptance_receipt_digests.get(receipt_digest, [])
            if len(matches) != 1:
                errors.append(
                    f"{label}: clean release receipt {receipt_instance.get('path')} "
                    "must have exactly one same-iteration repository acceptance "
                    f"for receiptDigest; found {len(matches)}"
                )
                continue
            acceptance, acceptance_instance = matches[0]
            acceptance_hash = acceptance_instance.get("sha256")
            if isinstance(acceptance_hash, str):
                matched_acceptance_hashes.add(acceptance_hash)
            _validate_clean_release_acceptance(
                acceptance,
                receipt,
                trust,
                f"clean release acceptance artifact {acceptance_instance.get('path')}",
                errors,
                correlation=(
                    acceptance_instance.get("correlation")
                    if isinstance(acceptance_instance.get("correlation"), Mapping)
                    else None
                ),
                subject_bindings=instance_subject_bindings.get(
                    id(acceptance_instance)
                ),
                iteration_finished=iteration_finished,
            )
        for acceptance_hash, (acceptance, instance) in clean_acceptances.items():
            if acceptance_hash not in matched_acceptance_hashes:
                errors.append(
                    f"{label}: clean release acceptance {instance.get('path')} "
                    f"does not uniquely bind a same-iteration signed receipt "
                    f"{acceptance.get('receiptDigest')!r}"
                )

        schedule_hash = iteration.get("scheduleTraceArtifactHash")
        _is_digest(schedule_hash, f"{label}.scheduleTraceArtifactHash", errors, nonzero=True)
        if schedule_hash not in correlated_hashes:
            errors.append(
                f"{label}.scheduleTraceArtifactHash: not correlated to this iteration"
            )
        barrier_hashes = _unique_strings(
            iteration.get("barrierObservationArtifactHashes"),
            f"{label}.barrierObservationArtifactHashes",
            errors,
        )
        _require_canonical_set_order(
            iteration.get("barrierObservationArtifactHashes"),
            f"{label}.barrierObservationArtifactHashes",
            errors,
        )
        for digest in barrier_hashes:
            _is_digest(digest, f"{label}.barrierObservationArtifactHashes", errors, nonzero=True)
            if digest not in correlated_hashes:
                errors.append(
                    f"{label}.barrierObservationArtifactHashes: {digest!r} is not "
                    "correlated to this iteration"
                )
        cleanup_hash = iteration.get("cleanupProofArtifactHash")
        _is_digest(cleanup_hash, f"{label}.cleanupProofArtifactHash", errors, nonzero=True)
        if cleanup_hash not in correlated_hashes:
            errors.append(
                f"{label}.cleanupProofArtifactHash: not correlated to this iteration"
            )
        cleanup_evidence = _validate_iteration_oracle_matrix(
            iteration.get("oracleResults"),
            expected_ids,
            correlated_hashes,
            f"{label}.oracleResults",
            errors,
        )
        if cleanup_hash not in cleanup_evidence:
            errors.append(
                f"{label}.cleanupProofArtifactHash: must be cited by this iteration's "
                "cleanup oracle matrix"
            )
    if observed_fault_counts != dict(fault_plan_counts):
        errors.append(
            "scenario.executionResult.iterationResults: observed fault-point counts "
            f"{observed_fault_counts!r} do not exactly equal plan {dict(fault_plan_counts)!r}"
        )
    if hashes_bound_to_valid_iterations != artifact_hashes:
        errors.append(
            "scenario.executionResult.artifactInstances: every artifact must correlate "
            "to exactly one declared iteration identity/fault point"
        )
    indexed_iteration_hashes = {
        digest
        for digest, artifact in index_artifacts.items()
        if artifact.get("iterationRunIdOrNull") is not None
    }
    if artifact_hashes != indexed_iteration_hashes:
        errors.append(
            "scenario.executionResult.artifactInstances: exact hashes must equal all "
            "iteration-scoped ExecutionEvidenceIndex artifacts"
        )
    _verify_signed_envelope(
        result,
        digest_field="resultDigest",
        signature_field="signature",
        signer_field="signerKeyId",
        signed_time_field="finishedAt",
        domain="QMAN-DIRECTPATH/ACCEPTANCE-EXECUTION/V1",
        required_role="TEST_EVIDENCE",
        trust=trust,
        label="scenario.executionResult",
        errors=errors,
    )


def _validate_scenario_document_core(
    scenario_document: Any,
    contract_document: Any,
    root: str | os.PathLike[str] | Path = ".",
    *,
    mapping_document: Any | None = None,
    trusted_root_digest: str | None = None,
    external_rollback_anchor: Any | None = None,
    trust_anchor_freshness_envelope: Any | None = None,
    verifier_nonce: str | None = None,
    _code_git_view: _GitView | None = None,
    _evidence_git_view: _GitView | None = None,
    _trust_context: _TrustContext | None = None,
    _risk_ids: set[str] | None = None,
) -> list[str]:
    """Validate a portable template, target binding, or passing execution."""

    errors: list[str] = []
    try:
        root_path = Path(root).resolve(strict=True)
    except OSError as exc:
        return [f"repository root: cannot resolve {root}: {exc}"]
    scenario = _coerce_document(scenario_document, "scenario", errors)
    contract = _coerce_document(contract_document, "portable contract", errors)
    mapping: Mapping[str, Any] | None = None
    if mapping_document is not None:
        candidate = _coerce_document(mapping_document, "integration map", errors)
        if isinstance(candidate, Mapping):
            mapping = candidate
    if not isinstance(scenario, Mapping) or not isinstance(contract, Mapping):
        return errors
    _validate_closed_json_schema_instance(
        scenario,
        root_path,
        "contracts/directpath-acceptance-scenario.schema.json",
        "scenario",
        errors,
    )
    risks = _risk_ids if _risk_ids is not None else _load_risk_ids(root_path, errors)
    code_git = _code_git_view
    evidence_git = _evidence_git_view
    trust = _trust_context
    if scenario.get("definitionStatus") in {"BOUND", "EXECUTED_PASS"} and mapping is not None:
        if code_git is None and isinstance(mapping.get("targetRepository"), Mapping):
            code_git = _GitView(
                root_path,
                mapping["targetRepository"],
                errors,
                "targetRepository",
            )
        if evidence_git is None and isinstance(mapping.get("evidenceRepository"), Mapping):
            evidence_git = _GitView(
                root_path,
                mapping["evidenceRepository"],
                errors,
                "evidenceRepository",
            )
            final_map_digest = mapping.get("mapDigest")
            if isinstance(final_map_digest, str) and final_map_digest:
                evidence_git.forbidden_blob_claims = (
                    final_map_digest.encode("ascii"),
                )
        if evidence_git is None:
            errors.append(
                "scenario: evidenceRepository E is required for BOUND/EXECUTED_PASS"
            )
        if trust is None:
            trust = _load_trust_context(
                mapping,
                evidence_git,
                root_path,
                errors,
                trusted_root_digest=trusted_root_digest,
                external_rollback_anchor=external_rollback_anchor,
                trust_anchor_freshness_envelope=trust_anchor_freshness_envelope,
                verifier_nonce=verifier_nonce,
                code_git=code_git,
            )
    try:
        _scenario_core(
            scenario,
            contract,
            root_path,
            errors,
            mapping=mapping,
            code_git=code_git,
            evidence_git=evidence_git,
            trust=trust,
            risks=risks,
        )
    except Exception as exc:
        errors.append(f"scenario: unexpected semantic validation failure: {type(exc).__name__}: {exc}")
    return errors


def validate_scenario_document(
    scenario_document: Any,
    contract_document: Any,
    root: str | os.PathLike[str] | Path = ".",
    *,
    mapping_document: Any | None = None,
    trusted_root_digest: str | None = None,
    external_rollback_anchor: Any | None = None,
    trust_anchor_freshness_envelope: Any | None = None,
    verifier_nonce: str | None = None,
    _code_git_view: _GitView | None = None,
    _evidence_git_view: _GitView | None = None,
    _trust_context: _TrustContext | None = None,
    _risk_ids: set[str] | None = None,
) -> list[str]:
    """Validate a scenario without accepting caller-injected trust state.

    The underscored parameters remain in the import API for compatibility, but
    authenticated repository/trust objects are capabilities created only by
    this module's private validation graph.  Public callers must supply the
    out-of-band bootstrap inputs and let the validator reconstruct them.
    """

    if any(
        value is not None
        for value in (
            _code_git_view,
            _evidence_git_view,
            _trust_context,
            _risk_ids,
        )
    ):
        return [
            "scenario: caller-injected private validation context is forbidden; "
            "supply repositories and out-of-band trust bootstrap inputs"
        ]
    return _validate_scenario_document_core(
        scenario_document,
        contract_document,
        root,
        mapping_document=mapping_document,
        trusted_root_digest=trusted_root_digest,
        external_rollback_anchor=external_rollback_anchor,
        trust_anchor_freshness_envelope=trust_anchor_freshness_envelope,
        verifier_nonce=verifier_nonce,
    )


def _canonical_string_union(values: Iterable[str]) -> list[str]:
    return sorted(set(values), key=canonical_json_bytes)


def _derive_platform_profile_digest(
    root: Path, platform_profile_id: Any, label: str, errors: list[str]
) -> str | None:
    """Recompute the portable technical platform profile projection."""

    policy_path = "contracts/compatibility-profile-policy.json"
    policy_blob = _worktree_bytes(root, policy_path, f"{label}.policy", errors)
    policy = (
        _load_json_bytes(policy_blob, f"{label}.policy", errors)
        if policy_blob is not None
        else None
    )
    if not isinstance(policy, Mapping):
        return None
    matching = [
        item
        for item in policy.get("platforms", [])
        if isinstance(item, Mapping) and item.get("id") == platform_profile_id
    ]
    if len(matching) != 1:
        errors.append(
            f"{label}.platformProfileId: expected exactly one active policy row, "
            f"found {len(matching)}"
        )
        return None
    projection = {
        "profileProjectionVersion": 1,
        "policySchemaVersion": policy.get("schemaVersion"),
        "capabilityTarget": policy.get("capabilityTarget"),
        "platform": copy.deepcopy(dict(matching[0])),
        "backendPolicy": copy.deepcopy(policy.get("backendPolicy")),
        "hostConfigurationPolicy": copy.deepcopy(
            policy.get("hostConfigurationPolicy")
        ),
    }
    return _canonical_digest(
        projection, f"{label}.platformProfileDigest projection", errors
    )


def _case_completion_evaluator_matches(
    evaluator: Any,
    scenario_bundles: Sequence[Mapping[str, Any]],
    completion: Mapping[str, Any],
    code_git: _GitView | None,
    evidence_git: _GitView | None,
    root: Path,
    mapping: Mapping[str, Any] | None,
    case_registry: Mapping[str, Any] | None,
    trust: _TrustContext | None,
    label: str,
    errors: list[str],
) -> None:
    evaluator_fields = {
        "protocol",
        "path",
        "blobSha256",
        "interfaceHash",
        "toolManifest",
    }
    _exact_keys(evaluator, evaluator_fields, f"{label}.evaluator", errors)
    if not isinstance(evaluator, Mapping):
        return
    if evaluator.get("protocol") != "QMAN-DIRECTPATH-CASE-COMPLETION-EVALUATOR-V1":
        errors.append(f"{label}.evaluator.protocol: unsupported protocol")
    evaluator_blob = (
        code_git.blob(evaluator.get("path"), f"{label}.evaluator.path", errors)
        if code_git is not None
        else None
    )
    if code_git is None:
        errors.append(f"{label}.evaluator: target repository C is unavailable")
    _check_blob_hash(
        evaluator_blob,
        evaluator.get("blobSha256"),
        f"{label}.evaluator",
        errors,
    )
    binding_matches: list[Mapping[str, Any]] = []
    if isinstance(mapping, Mapping):
        for entry in mapping.get("mappings", []):
            if not isinstance(entry, Mapping):
                continue
            for binding in entry.get("targetBindings", []):
                if (
                    isinstance(binding, Mapping)
                    and binding.get("path") == evaluator.get("path")
                    and binding.get("interfaceHash") == evaluator.get("interfaceHash")
                    and binding.get("symbolKind") in {"FUNCTION", "TEST"}
                ):
                    binding_matches.append(binding)
    if len(binding_matches) != 1:
        errors.append(
            f"{label}.evaluator: path/interface resolves {len(binding_matches)} "
            "signed target bindings; expected exactly one"
        )

    manifest_descriptor = evaluator.get("toolManifest")
    descriptor_fields = {
        "path",
        "sha256",
        "byteLength",
        "mediaType",
        "schemaRef",
        "schemaSha256",
        "manifestDigest",
    }
    manifest_blob = _typed_artifact_from_git(
        manifest_descriptor,
        evidence_git,
        root,
        f"{label}.evaluator.toolManifest",
        errors,
        expected_schema_ref=(
            "contracts/directpath-case-evaluator-tool-manifest.schema.json"
        ),
        descriptor_fields=descriptor_fields,
    )
    if not isinstance(manifest_descriptor, Mapping) or manifest_blob is None:
        return
    if manifest_descriptor.get("mediaType") != "application/json":
        errors.append(
            f"{label}.evaluator.toolManifest.mediaType: expected application/json"
        )
    if manifest_descriptor.get("byteLength") != len(manifest_blob):
        errors.append(
            f"{label}.evaluator.toolManifest.byteLength: declared "
            f"{manifest_descriptor.get('byteLength')!r}, actual {len(manifest_blob)}"
        )
    manifest = _load_json_bytes(
        manifest_blob, f"{label}.evaluator.toolManifest", errors
    )
    if not isinstance(manifest, Mapping):
        return
    _verify_signed_envelope(
        manifest,
        digest_field="manifestDigest",
        signature_field="signature",
        signer_field="signerKeyId",
        signed_time_field="createdAt",
        domain="QMAN-DIRECTPATH/CASE-EVALUATOR-TOOL-MANIFEST/V1",
        required_role="TEST_EVIDENCE",
        trust=trust,
        label=f"{label}.evaluator.toolManifest",
        errors=errors,
    )
    if manifest_descriptor.get("manifestDigest") != manifest.get("manifestDigest"):
        errors.append(
            f"{label}.evaluator.toolManifest.manifestDigest: parsed manifest mismatch"
        )
    exact_manifest_fields = {
        "targetRepositoryCommit": completion.get("targetRepositoryCommit"),
        "mappingCoreId": completion.get("mappingCoreId"),
        "portableContractSha256": completion.get("portableContractSha256"),
        "caseContractRegistryDigest": completion.get(
            "caseContractRegistryDigest"
        ),
        "evaluator": {
            "protocol": evaluator.get("protocol"),
            "path": evaluator.get("path"),
            "blobSha256": evaluator.get("blobSha256"),
            "interfaceHash": evaluator.get("interfaceHash"),
        },
    }
    for field, expected in exact_manifest_fields.items():
        actual = manifest.get(field)
        if field == "targetRepositoryCommit":
            actual = _normal_commit(
                actual,
                f"{label}.evaluator.toolManifest.targetRepositoryCommit",
                errors,
            )
            expected = _normal_commit(
                expected, f"{label}.targetRepositoryCommit", errors
            )
        if actual != expected:
            errors.append(
                f"{label}.evaluator.toolManifest.{field}: expected {expected!r}"
            )
    if isinstance(case_registry, Mapping) and manifest.get(
        "caseContractRegistryDigest"
    ) != case_registry.get("registryDigest"):
        errors.append(
            f"{label}.evaluator.toolManifest.caseContractRegistryDigest: "
            "independent registry mismatch"
        )

    source_tree = manifest.get("sourceTree")
    if isinstance(source_tree, Mapping):
        if (
            source_tree.get("path") == manifest_descriptor.get("path")
            or source_tree.get("sha256") == manifest_descriptor.get("sha256")
        ):
            errors.append(
                f"{label}.evaluator.toolManifest.sourceTree: manifest and "
                "source-tree roles require distinct paths and hashes"
            )
        tracked_paths: set[str] = set()
        source_tree_blob = (
            evidence_git.blob(
                source_tree.get("path"),
                f"{label}.evaluator.toolManifest.sourceTree.path",
                errors,
            )
            if evidence_git is not None
            else None
        )
        if source_tree_blob is not None and source_tree.get("byteLength") != len(
            source_tree_blob
        ):
            errors.append(
                f"{label}.evaluator.toolManifest.sourceTree.byteLength: mismatch"
            )
        if source_tree.get("mediaType") != "application/json":
            errors.append(
                f"{label}.evaluator.toolManifest.sourceTree.mediaType: expected "
                "application/json"
            )
        source_manifest = _validate_source_tree_manifest(
            {
                "sourceTreeManifestPath": source_tree.get("path"),
                "sourceTreeManifestSha256": source_tree.get("sha256"),
                "sourceTreeManifestSchemaSha256": source_tree.get("schemaSha256"),
                "sourceTreeSha256": source_tree.get("sourceTreeSha256"),
            },
            code_git,
            evidence_git,
            root,
            f"{label}.evaluator.toolManifest.sourceTree",
            errors,
            _tracked_paths=tracked_paths,
        )
        if isinstance(source_manifest, Mapping):
            if evaluator.get("path") not in tracked_paths:
                errors.append(
                    f"{label}.evaluator.toolManifest.sourceTree: evaluator path "
                    "is absent from the exact tracked tree"
                )

    build_bundle = _validate_build_attestation(
        manifest.get("buildAttestation"),
        expected_consumer_kind="CASE_EVALUATOR",
        expected_consumer_build_id=manifest.get("manifestId"),
        expected_target_commit=manifest.get("targetRepositoryCommit"),
        expected_mapping_core_id=manifest.get("mappingCoreId"),
        expected_portable_contract_sha256=manifest.get("portableContractSha256"),
        expected_source_tree=(dict(source_tree) if isinstance(source_tree, Mapping) else None),
        code_git=code_git,
        evidence_git=evidence_git,
        root=root,
        trust=trust,
        label=f"{label}.evaluator.toolManifest.buildAttestation",
        errors=errors,
    )
    build_attestation: Mapping[str, Any] | None = None
    build_artifacts: Mapping[str, Any] | None = None
    if isinstance(build_bundle, Mapping):
        candidate_attestation = build_bundle.get("attestation")
        candidate_artifacts = build_bundle.get("artifacts")
        if isinstance(candidate_attestation, Mapping):
            build_attestation = candidate_attestation
            attested_at = _parse_time(
                build_attestation.get("attestedAt"),
                f"{label}.evaluator.toolManifest.buildAttestation.attestedAt",
                errors,
            )
            manifest_created = _parse_time(
                manifest.get("createdAt"),
                f"{label}.evaluator.toolManifest.createdAt",
                errors,
            )
            if (
                attested_at is not None
                and manifest_created is not None
                and attested_at >= manifest_created
            ):
                errors.append(
                    f"{label}.evaluator.toolManifest.createdAt: must strictly "
                    "follow complete BuildAttestation"
                )
        if isinstance(candidate_artifacts, Mapping):
            build_artifacts = candidate_artifacts

    environment = manifest.get("executionEnvironment")
    artifacts: list[Mapping[str, Any]] = []
    if isinstance(environment, Mapping):
        for role in (
            "runtimeBinary",
            "dependencyLock",
            "environmentManifest",
            "buildLog",
        ):
            artifact = environment.get(role)
            artifact_label = (
                f"{label}.evaluator.toolManifest.executionEnvironment.{role}"
            )
            if not isinstance(artifact, Mapping):
                errors.append(f"{artifact_label}: expected closed artifact descriptor")
                continue
            artifacts.append(artifact)
            artifact_blob = (
                evidence_git.blob(artifact.get("path"), f"{artifact_label}.path", errors)
                if evidence_git is not None
                else None
            )
            _check_blob_hash(
                artifact_blob, artifact.get("sha256"), artifact_label, errors
            )
            if artifact_blob is not None and artifact.get("byteLength") != len(
                artifact_blob
            ):
                errors.append(
                    f"{artifact_label}.byteLength: declared "
                    f"{artifact.get('byteLength')!r}, actual {len(artifact_blob)}"
                )
    if (
        isinstance(build_attestation, Mapping)
        and isinstance(environment, Mapping)
        and isinstance(build_artifacts, Mapping)
    ):
        mode = build_attestation.get("mode")
        output = build_attestation.get("output")
        runtime_binary = environment.get("runtimeBinary")
        if mode == "INTERPRETED_NO_BUILD":
            if environment.get("mode") != "INTERPRETED":
                errors.append(
                    f"{label}.evaluator.toolManifest.executionEnvironment.mode: "
                    "interpreted BuildAttestation requires INTERPRETED"
                )
            if (
                not isinstance(output, Mapping)
                or output.get("kind") != "INTERPRETED_RUNTIME"
                or output.get("role") != "CASE_EVALUATOR_SOURCE"
            ):
                errors.append(
                    f"{label}.evaluator.toolManifest.buildAttestation.output: "
                    "expected CASE_EVALUATOR_SOURCE interpreted runtime"
                )
            elif isinstance(output.get("entrypointSource"), Mapping):
                entrypoint = output["entrypointSource"]
                if (
                    entrypoint.get("path") != evaluator.get("path")
                    or entrypoint.get("contentSha256")
                    != evaluator.get("blobSha256")
                ):
                    errors.append(
                        f"{label}.evaluator.toolManifest.buildAttestation.output: "
                        "entrypoint does not equal evaluator source"
                    )
            interpreter_component = None
            toolchain = build_attestation.get("toolchain")
            if isinstance(toolchain, Mapping):
                matches = [
                    component
                    for component in toolchain.get("components", [])
                    if isinstance(component, Mapping)
                    and component.get("componentId")
                    == (output.get("interpreterComponentId") if isinstance(output, Mapping) else None)
                ]
                if len(matches) == 1:
                    interpreter_component = matches[0]
            interpreter_artifact = (
                interpreter_component.get("artifact")
                if isinstance(interpreter_component, Mapping)
                else None
            )
            if runtime_binary != interpreter_artifact:
                errors.append(
                    f"{label}.evaluator.toolManifest.executionEnvironment."
                    "runtimeBinary: interpreter artifact mismatch"
                )
        else:
            if environment.get("mode") == "INTERPRETED":
                errors.append(
                    f"{label}.evaluator.toolManifest.executionEnvironment.mode: "
                    "produced evaluator cannot use INTERPRETED"
                )
            if isinstance(output, Mapping) and output.get(
                "consumerRuntimeMode"
            ) != environment.get("mode"):
                errors.append(
                    f"{label}.evaluator.toolManifest.executionEnvironment.mode: "
                    "produced output consumerRuntimeMode mismatch"
                )
            if (
                not isinstance(output, Mapping)
                or output.get("kind") != "PRODUCED_ARTIFACT"
                or output.get("role") != "CASE_EVALUATOR_BINARY"
                or output.get("executable") is not True
            ):
                errors.append(
                    f"{label}.evaluator.toolManifest.buildAttestation.output: "
                    "expected executable CASE_EVALUATOR_BINARY"
                )
            elif runtime_binary != output.get("artifact"):
                errors.append(
                    f"{label}.evaluator.toolManifest.executionEnvironment."
                    "runtimeBinary: produced output mismatch"
                )
        exact_runtime_artifacts = {
            "dependencyLock": build_artifacts.get("dependencies.lockArtifact"),
            "environmentManifest": build_artifacts.get("environment.manifest"),
            "buildLog": build_artifacts.get("buildLog"),
        }
        for role, expected in exact_runtime_artifacts.items():
            if environment.get(role) != expected:
                errors.append(
                    f"{label}.evaluator.toolManifest.executionEnvironment.{role}: "
                    "BuildAttestation mismatch"
                )
    artifact_paths = [
        item.get("path")
        for item in artifacts
        if isinstance(item.get("path"), str)
    ]
    artifact_hashes = [
        item.get("sha256")
        for item in artifacts
        if isinstance(item.get("sha256"), str)
    ]
    if len(set(artifact_paths)) != 4 or len(set(artifact_hashes)) != 4:
        errors.append(
            f"{label}.evaluator.toolManifest.executionEnvironment: four artifacts "
            "must have pairwise-distinct paths and hashes"
        )

    forbidden_paths: set[str] = set()
    forbidden_hashes: set[str] = set()
    if isinstance(manifest_descriptor.get("path"), str):
        forbidden_paths.add(manifest_descriptor["path"])
    if isinstance(manifest_descriptor.get("sha256"), str):
        forbidden_hashes.add(manifest_descriptor["sha256"])
    scenario_runner_paths: set[str] = set()
    scenario_runner_hashes: set[str] = set()
    scenario_control_paths: set[str] = set()
    scenario_control_hashes: set[str] = set()
    if isinstance(source_tree, Mapping):
        if isinstance(source_tree.get("path"), str):
            forbidden_paths.add(source_tree["path"])
        if isinstance(source_tree.get("sha256"), str):
            forbidden_hashes.add(source_tree["sha256"])
    build_descriptor = manifest.get("buildAttestation")
    if isinstance(build_descriptor, Mapping):
        if isinstance(build_descriptor.get("path"), str):
            forbidden_paths.add(build_descriptor["path"])
        if isinstance(build_descriptor.get("sha256"), str):
            forbidden_hashes.add(build_descriptor["sha256"])
    for bundle in scenario_bundles:
        scenario = bundle.get("scenario")
        index = bundle.get("index")
        if isinstance(scenario, Mapping):
            result = scenario.get("executionResult")
            target = scenario.get("targetBinding")
            if isinstance(result, Mapping) and isinstance(
                result.get("runnerManifestPath"), str
            ):
                scenario_runner_paths.add(result["runnerManifestPath"])
            if isinstance(target, Mapping):
                if isinstance(target.get("runnerManifestPath"), str):
                    scenario_runner_paths.add(target["runnerManifestPath"])
                if isinstance(target.get("runnerManifestSha256"), str):
                    scenario_runner_hashes.add(target["runnerManifestSha256"])
        if isinstance(index, Mapping):
            controls = index.get("requiredControlArtifactHashes")
            if isinstance(controls, Mapping):
                control_hashes = {
                    value for value in controls.values() if isinstance(value, str)
                }
                scenario_control_hashes.update(control_hashes)
                forbidden_hashes.update(control_hashes)
                for artifact in index.get("artifacts", []):
                    if (
                        isinstance(artifact, Mapping)
                        and artifact.get("sha256") in control_hashes
                    ):
                        artifact_path = artifact.get("path")
                        if isinstance(artifact_path, str):
                            scenario_control_paths.add(artifact_path)
                            forbidden_paths.add(artifact_path)
    forbidden_paths.update(scenario_runner_paths)
    forbidden_hashes.update(scenario_runner_hashes)
    manifest_path = manifest_descriptor.get("path")
    manifest_hash = manifest_descriptor.get("sha256")
    if (
        isinstance(manifest_path, str)
        and manifest_path in scenario_runner_paths | scenario_control_paths
    ) or (
        isinstance(manifest_hash, str)
        and manifest_hash in scenario_runner_hashes | scenario_control_hashes
    ):
        errors.append(
            f"{label}.evaluator.toolManifest: Scenario RunnerManifest/control "
            "artifact reuse is forbidden"
        )
    for number, artifact in enumerate(artifacts):
        artifact_path = artifact.get("path")
        artifact_hash = artifact.get("sha256")
        if (
            isinstance(artifact_path, str) and artifact_path in forbidden_paths
        ) or (
            isinstance(artifact_hash, str) and artifact_hash in forbidden_hashes
        ):
            errors.append(
                f"{label}.evaluator.toolManifest.executionEnvironment artifact "
                f"{number}: reuses a manifest/source-tree/Scenario-control role"
            )


def _validate_case_completion_artifact(
    descriptor: Any,
    *,
    descriptor_fields: set[str],
    expected_platform_id: Any,
    code_git: _GitView | None,
    evidence_git: _GitView | None,
    root: Path,
    contract: Mapping[str, Any],
    mapping: Mapping[str, Any] | None,
    trust: _TrustContext | None,
    case_registry: Mapping[str, Any] | None,
    label: str,
    errors: list[str],
) -> Mapping[str, Any] | None:
    """Resolve and independently re-derive one signed CaseCompletionRecord."""

    blob = _typed_artifact_from_git(
        descriptor,
        evidence_git,
        root,
        label,
        errors,
        expected_schema_ref="contracts/directpath-case-completion-record.schema.json",
        descriptor_fields=descriptor_fields,
    )
    completion = _load_json_bytes(blob, label, errors) if blob is not None else None
    if not isinstance(descriptor, Mapping) or not isinstance(completion, Mapping):
        return None
    _validate_closed_json_schema_instance(
        completion,
        root,
        "contracts/directpath-case-completion-record.schema.json",
        label,
        errors,
    )
    if completion.get("schemaVersion") != 1:
        errors.append(f"{label}.schemaVersion: expected 1")
    grade = completion.get("evidenceGrade")
    required_role = {
        "E3-END-TO-END-PRODUCT": "TEST_EVIDENCE",
        "E4-PHYSICAL-QUALIFICATION": "QUALIFICATION_ENGINEERING",
    }.get(grade)
    if required_role is None:
        errors.append(f"{label}.evidenceGrade: unsupported grade")
    else:
        _verify_signed_envelope(
            completion,
            digest_field="completionDigest",
            signature_field="signature",
            signer_field="signerKeyId",
            signed_time_field="completedAt",
            domain="QMAN-DIRECTPATH/CASE-COMPLETION/V1",
            required_role=required_role,
            trust=trust,
            label=label,
            errors=errors,
        )

    records = (
        case_registry.get("records", [])
        if isinstance(case_registry, Mapping)
        else []
    )
    case_by_id = {
        item.get("caseId"): item
        for item in records
        if isinstance(item, Mapping) and isinstance(item.get("caseId"), str)
    }
    case_id = completion.get("caseId")
    case_record = case_by_id.get(case_id)
    if not isinstance(case_record, Mapping):
        errors.append(f"{label}.caseId: unknown current generated Case {case_id!r}")
        return None
    classification = case_record.get("classification")
    if not isinstance(classification, Mapping) or (
        classification.get("scope"), classification.get("status")
    ) != ("PRODUCT", "EXECUTABLE"):
        errors.append(
            f"{label}: Case {case_id!r} is not current PRODUCT/EXECUTABLE and "
            "cannot be completed"
        )
    expected_portable_hash = None
    expected_mapping_core = None
    if isinstance(mapping, Mapping):
        source = mapping.get("sourceContract")
        expected_portable_hash = source.get("sha256") if isinstance(source, Mapping) else None
        expected_mapping_core = mapping.get("mappingCoreId")
    expected_commit = code_git.commit if code_git is not None else None
    exact_completion_fields = {
        "caseId": case_id,
        "sourceCaseStatus": "EXECUTABLE",
        "scope": "PRODUCT",
        "caseContractDigest": case_record.get("caseContractDigest"),
        "caseContractRegistryDigest": (
            case_registry.get("registryDigest")
            if isinstance(case_registry, Mapping)
            else None
        ),
        "portableContractSha256": expected_portable_hash,
        "targetRepositoryCommit": expected_commit,
        "mappingCoreId": expected_mapping_core,
    }
    for field, expected in exact_completion_fields.items():
        actual = completion.get(field)
        normalized = (
            _normal_commit(actual, f"{label}.{field}", errors)
            if field == "targetRepositoryCommit"
            else actual
        )
        if normalized != expected:
            errors.append(f"{label}.{field}: expected {expected!r}")

    signed_platform_id = completion.get("platformProfileId")
    if signed_platform_id != expected_platform_id:
        errors.append(
            f"{label}.platformProfileId: signed value differs from outer descriptor"
        )
    expected_platform_digest = _derive_platform_profile_digest(
        root, signed_platform_id, label, errors
    )
    if completion.get("platformProfileDigest") != expected_platform_digest:
        errors.append(
            f"{label}.platformProfileDigest: declared "
            f"{completion.get('platformProfileDigest')!r}, actual "
            f"{expected_platform_digest!r}"
        )
    _is_digest(
        completion.get("backendProfileDigest"),
        f"{label}.backendProfileDigest",
        errors,
        nonzero=True,
    )
    exact_qualification_key = completion.get("exactQualificationKey")
    if grade == "E3-END-TO-END-PRODUCT":
        if exact_qualification_key is not None:
            errors.append(f"{label}.exactQualificationKey: E3 requires null")
    elif grade == "E4-PHYSICAL-QUALIFICATION":
        _is_digest(
            exact_qualification_key,
            f"{label}.exactQualificationKey",
            errors,
            nonzero=True,
        )

    descriptor_expectations = {
        "caseId": completion.get("caseId"),
        "scope": completion.get("scope"),
        "sourceCaseStatus": completion.get("sourceCaseStatus"),
        "caseContractDigest": completion.get("caseContractDigest"),
        "caseContractRegistryDigest": completion.get("caseContractRegistryDigest"),
        "portableContractSha256": completion.get("portableContractSha256"),
        "mappingCoreId": completion.get("mappingCoreId"),
        "completionDigest": completion.get("completionDigest"),
        "evidenceGrade": completion.get("evidenceGrade"),
    }
    for field, expected in descriptor_expectations.items():
        if field in descriptor and descriptor.get(field) != expected:
            errors.append(f"{label} descriptor.{field}: parsed completion mismatch")
    descriptor_commit = (
        descriptor.get("targetRepositoryCommit")
        if "targetRepositoryCommit" in descriptor
        else descriptor.get("targetCommit")
    )
    normalized_descriptor_commit = _normal_commit(
        descriptor_commit, f"{label} descriptor.targetCommit", errors
    )
    if normalized_descriptor_commit != expected_commit:
        errors.append(f"{label} descriptor.targetCommit: target C mismatch")
    if descriptor.get("platformProfileId") != expected_platform_id:
        errors.append(f"{label} descriptor.platformProfileId: outer platform mismatch")
    if "platformProfileId" in descriptor and descriptor.get(
        "platformProfileId"
    ) != signed_platform_id:
        errors.append(
            f"{label} descriptor.platformProfileId: parsed completion mismatch"
        )
    if "exactQualificationKey" in descriptor and descriptor.get(
        "exactQualificationKey"
    ) != exact_qualification_key:
        errors.append(
            f"{label} descriptor.exactQualificationKey: parsed completion mismatch"
        )

    scenario_rows = completion.get("scenarioEvidence")
    if not isinstance(scenario_rows, list) or not scenario_rows:
        errors.append(f"{label}.scenarioEvidence: expected non-empty array")
        scenario_rows = []
    observed_order: list[bytes] = []
    derived_rows: list[dict[str, Any]] = []
    scenario_bundles: list[Mapping[str, Any]] = []
    scenario_identities: set[tuple[Any, ...]] = set()
    core_digests: set[Any] = set()
    index_digests: set[Any] = set()
    runner_digests: set[Any] = set()
    raw_hashes: set[Any] = set()
    runner_raw_hashes: set[Any] = set()
    fault_repeats: dict[str, int] = {}
    for number, declared in enumerate(scenario_rows):
        row_label = f"{label}.scenarioEvidence[{number}]"
        if not isinstance(declared, Mapping):
            errors.append(f"{row_label}: expected object")
            continue
        try:
            observed_order.append(
                canonical_json_bytes(
                    [declared.get("scenarioId"), declared.get("scenarioRunId")]
                )
            )
        except (CanonicalizationError, TypeError, ValueError) as exc:
            errors.append(f"{row_label}: invalid canonical order key: {exc}")
        scenario_blob = (
            evidence_git.blob(declared.get("scenarioPath"), f"{row_label}.scenarioPath", errors)
            if evidence_git is not None
            else None
        )
        _check_blob_hash(
            scenario_blob,
            declared.get("scenarioSha256"),
            f"{row_label}.scenario",
            errors,
        )
        scenario = (
            _load_json_bytes(scenario_blob, f"{row_label}.scenario", errors)
            if scenario_blob is not None
            else None
        )
        if not isinstance(scenario, Mapping):
            continue
        scenario_errors = _validate_scenario_document_core(
            scenario,
            contract,
            root=root,
            mapping_document=mapping,
            _code_git_view=code_git,
            _evidence_git_view=evidence_git,
            _trust_context=trust,
        )
        errors.extend(f"{row_label}.scenario: {item}" for item in scenario_errors)
        result = scenario.get("executionResult")
        target = scenario.get("targetBinding")
        applicability = scenario.get("applicability")
        trace = scenario.get("traceability")
        if not isinstance(result, Mapping):
            errors.append(f"{row_label}: signed executionResult is missing")
            continue
        if scenario.get("definitionStatus") != "EXECUTED_PASS":
            errors.append(f"{row_label}: only EXECUTED_PASS may aggregate")
        if scenario.get("caseId") != case_id:
            errors.append(f"{row_label}.caseId: completion Case mismatch")
        platform_values = (
            applicability.get("platformProfileIds", [])
            if isinstance(applicability, Mapping)
            else []
        )
        if platform_values != [signed_platform_id]:
            errors.append(
                f"{row_label}: applicability must identify exactly platform "
                f"{signed_platform_id!r}"
            )
        if grade == "E4-PHYSICAL-QUALIFICATION" and (
            not isinstance(applicability, Mapping)
            or applicability.get("requiresPhysicalHardware") is not True
        ):
            errors.append(f"{row_label}: E4 completion requires physical hardware")
        if not isinstance(target, Mapping) or target.get("mappingCoreId") != expected_mapping_core:
            errors.append(f"{row_label}: target binding mapping core mismatch")
        elif (
            target.get("platformProfileDigest")
            != completion.get("platformProfileDigest")
        ):
            errors.append(
                f"{row_label}.targetBinding.platformProfileDigest: signed "
                "CaseCompletion mismatch"
            )
        if isinstance(target, Mapping) and target.get(
            "backendProfileDigest"
        ) != completion.get("backendProfileDigest"):
            errors.append(
                f"{row_label}.targetBinding.backendProfileDigest: signed "
                "CaseCompletion mismatch"
            )

        index_blob = (
            evidence_git.blob(
                declared.get("executionEvidenceIndexPath"),
                f"{row_label}.executionEvidenceIndexPath",
                errors,
            )
            if evidence_git is not None
            else None
        )
        _check_blob_hash(
            index_blob,
            declared.get("evidenceIndexRecordSha256"),
            f"{row_label}.ExecutionEvidenceIndex",
            errors,
        )
        index = (
            _load_json_bytes(index_blob, f"{row_label}.ExecutionEvidenceIndex", errors)
            if index_blob is not None
            else None
        )
        runner_blob = (
            evidence_git.blob(
                declared.get("runnerManifestPath"),
                f"{row_label}.runnerManifestPath",
                errors,
            )
            if evidence_git is not None
            else None
        )
        _check_blob_hash(
            runner_blob,
            declared.get("runnerManifestSha256"),
            f"{row_label}.RunnerManifest",
            errors,
        )
        runner = (
            _load_json_bytes(runner_blob, f"{row_label}.RunnerManifest", errors)
            if runner_blob is not None
            else None
        )
        if not isinstance(index, Mapping) or not isinstance(runner, Mapping):
            continue
        if declared.get("executionEvidenceIndexPath") != result.get(
            "executionEvidenceIndexPath"
        ) or declared.get("evidenceIndexRecordSha256") != result.get(
            "evidenceIndexRecordSha256"
        ):
            errors.append(f"{row_label}: raw index descriptor does not bind executionResult")
        if declared.get("runnerManifestPath") != result.get("runnerManifestPath"):
            errors.append(f"{row_label}: runner path does not bind executionResult")
        if isinstance(target, Mapping) and (
            declared.get("runnerManifestPath") != target.get("runnerManifestPath")
            or declared.get("runnerManifestSha256") != target.get("runnerManifestSha256")
        ):
            errors.append(f"{row_label}: runner raw bytes do not bind targetBinding")
        core_digest = _scenario_execution_core_digest(result, errors)
        iterations = result.get("iterationResults")
        if not isinstance(iterations, list):
            iterations = []
        repeat = len(iterations)
        fault_classes = _canonical_string_union(
            fault
            for iteration in iterations
            if isinstance(iteration, Mapping)
            for fault in iteration.get("faultClasses", [])
            if isinstance(fault, str)
        )
        for iteration in iterations:
            if not isinstance(iteration, Mapping):
                continue
            for fault in set(iteration.get("faultClasses", [])):
                if isinstance(fault, str):
                    fault_repeats[fault] = fault_repeats.get(fault, 0) + 1
        binding_digests = _canonical_string_union(
            item.get("assertionDigest")
            for item in scenario.get("casePredicateBindings", [])
            if isinstance(item, Mapping) and isinstance(item.get("assertionDigest"), str)
        )
        derived = {
            "scenarioId": scenario.get("scenarioId"),
            "scenarioRunId": result.get("runId"),
            "scenarioPath": declared.get("scenarioPath"),
            "scenarioSha256": declared.get("scenarioSha256"),
            "scenarioExecutionCoreDigest": core_digest,
            "executionEvidenceIndexPath": result.get("executionEvidenceIndexPath"),
            "evidenceIndexRecordSha256": result.get("evidenceIndexRecordSha256"),
            "executionEvidenceIndexDigest": index.get("indexDigest"),
            "executionResultDigest": result.get("resultDigest"),
            "runnerManifestPath": result.get("runnerManifestPath"),
            "runnerManifestSha256": declared.get("runnerManifestSha256"),
            "runnerManifestDigest": runner.get("manifestDigest"),
            "repeat": repeat,
            "observedDurationSeconds": index.get("observedDurationSeconds"),
            "faultClasses": fault_classes,
            "portIds": _canonical_string_union(
                trace.get("portIds", []) if isinstance(trace, Mapping) else []
            ),
            "operationIds": _canonical_string_union(
                trace.get("operationIds", []) if isinstance(trace, Mapping) else []
            ),
            "transitionIds": _canonical_string_union(
                trace.get("transitionIds", []) if isinstance(trace, Mapping) else []
            ),
            "artifactSchemaRefs": _case_completion_observed_artifact_schema_refs(
                index
            ),
            "oracleClasses": _canonical_string_union(ORACLE_CATEGORY_FIELDS),
            "assertionDigests": binding_digests,
        }
        if dict(declared) != derived:
            differing = sorted(
                field
                for field in set(declared) | set(derived)
                if declared.get(field) != derived.get(field)
            )
            errors.append(
                f"{row_label}: declared row differs from independent derivation {differing}"
            )
        if index.get("scenarioExecutionCoreDigest") != core_digest:
            errors.append(f"{row_label}: index execution-core digest mismatch")
        if index.get("indexDigest") != result.get("executionEvidenceIndexDigest"):
            errors.append(f"{row_label}: index internal digest mismatch")
        if runner.get("manifestDigest") != result.get("runnerManifestDigest"):
            errors.append(f"{row_label}: runner internal digest mismatch")
        if index.get("evidenceGrade") != grade:
            errors.append(f"{row_label}: evidence grade differs from completion")
        identity = (
            scenario.get("scenarioId"),
            result.get("runId"),
            core_digest,
            index.get("indexDigest"),
            runner.get("manifestDigest"),
        )
        if identity in scenario_identities:
            errors.append(f"{row_label}: duplicate/reused scenario evidence identity")
        scenario_identities.add(identity)
        core_digests.add(core_digest)
        index_digests.add(index.get("indexDigest"))
        runner_digests.add(runner.get("manifestDigest"))
        for digest in (
            declared.get("scenarioSha256"),
            declared.get("evidenceIndexRecordSha256"),
        ):
            if digest in raw_hashes:
                errors.append(f"{row_label}: raw evidence blob is reused")
            raw_hashes.add(digest)
        runner_raw_digest = declared.get("runnerManifestSha256")
        if isinstance(runner_raw_digest, str):
            runner_raw_hashes.add(runner_raw_digest)
        derived_rows.append(derived)
        bundle: dict[str, Any] = {
            "scenario": scenario,
            "index": index,
            "runner": runner,
        }
        if grade == "E4-PHYSICAL-QUALIFICATION":
            e4_bundle = _load_e4_evidence_bundle(
                scenario, evidence_git, root, trust, row_label, errors
            )
            if isinstance(e4_bundle, Mapping):
                bundle.update(e4_bundle)
        scenario_bundles.append(bundle)
    if observed_order != sorted(observed_order) or len(observed_order) != len(
        set(observed_order)
    ):
        errors.append(
            f"{label}.scenarioEvidence: rows must be unique and canonically sorted "
            "by [scenarioId,scenarioRunId]"
        )
    if grade == "E4-PHYSICAL-QUALIFICATION" and scenario_bundles:
        subjects = [item.get("subject") for item in scenario_bundles]
        subject_blobs = [item.get("subjectBlob") for item in scenario_bundles]
        if not all(isinstance(item, Mapping) for item in subjects):
            errors.append(f"{label}.E4Subject: every E4 index must resolve a subject")
        elif not all(isinstance(item, bytes) for item in subject_blobs) or len(
            set(subject_blobs)
        ) != 1:
            errors.append(
                f"{label}.E4Subject: every E4 index must resolve byte-identical "
                "subject bytes"
            )
        else:
            subject = subjects[0]
            assert isinstance(subject, Mapping)
            runtime = subject.get("kernelQemuFirmwareBackend")
            runtime_platform = (
                runtime.get("platformProfileId")
                if isinstance(runtime, Mapping)
                else None
            )
            if runtime_platform != signed_platform_id:
                errors.append(
                    f"{label}.E4Subject.kernelQemuFirmwareBackend.platformProfileId: "
                    "signed CaseCompletion mismatch"
                )
            if subject.get("platformProfileHash") != completion.get(
                "platformProfileDigest"
            ):
                errors.append(
                    f"{label}.E4Subject.platformProfileHash: signed "
                    "CaseCompletion mismatch"
                )
            backend_digest = _canonical_digest(
                runtime, f"{label}.E4Subject.backendProfileDigest projection", errors
            )
            if backend_digest != completion.get("backendProfileDigest"):
                errors.append(
                    f"{label}.E4Subject.backendProfileDigest: declared "
                    f"{completion.get('backendProfileDigest')!r}, actual "
                    f"{backend_digest!r}"
                )
            exact_key_projection = {
                field: copy.deepcopy(subject.get(field))
                for field in (
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
            derived_exact_key = _canonical_digest(
                exact_key_projection,
                f"{label}.E4Subject.exactQualificationKey projection",
                errors,
            )
            if (
                completion.get("exactQualificationKey") != derived_exact_key
                or subject.get("derivedExactQualificationKey") != derived_exact_key
            ):
                errors.append(
                    f"{label}.E4Subject.derivedExactQualificationKey: must equal "
                    "the independently derived signed CaseCompletion key"
                )
            subject_case_ids = subject.get("caseIds")
            if not isinstance(subject_case_ids, list) or case_id not in subject_case_ids:
                errors.append(
                    f"{label}.E4Subject.caseIds: does not contain completion Case"
                )
            declared_core_values = subject.get("scenarioExecutionCoreDigests")
            declared_subject_cores = (
                {item for item in declared_core_values if isinstance(item, str)}
                if isinstance(declared_core_values, list)
                else set()
            )
            missing_subject_cores = set(core_digests) - declared_subject_cores
            if missing_subject_cores:
                errors.append(
                    f"{label}.E4Subject.scenarioExecutionCoreDigests: missing "
                    f"completion cores {sorted(missing_subject_cores)}"
                )

    coverage = completion.get("observedCoverage")
    derived_coverage = {
        "portIds": _canonical_string_union(
            value for row in derived_rows for value in row["portIds"]
        ),
        "operationIds": _canonical_string_union(
            value for row in derived_rows for value in row["operationIds"]
        ),
        "transitionIds": _canonical_string_union(
            value for row in derived_rows for value in row["transitionIds"]
        ),
        "faultClasses": _canonical_string_union(
            value for row in derived_rows for value in row["faultClasses"]
        ),
        "artifactSchemaRefs": _canonical_string_union(
            value for row in derived_rows for value in row["artifactSchemaRefs"]
        ),
        "oracleClasses": _canonical_string_union(
            value for row in derived_rows for value in row["oracleClasses"]
        ),
        "assertionDigests": _canonical_string_union(
            value for row in derived_rows for value in row["assertionDigests"]
        ),
        "repeatByFaultClass": [
            {"faultClass": fault, "repeat": fault_repeats[fault]}
            for fault in sorted(fault_repeats, key=canonical_json_bytes)
        ],
        "totalObservedDurationSeconds": sum(
            row["observedDurationSeconds"]
            for row in derived_rows
            if isinstance(row.get("observedDurationSeconds"), int)
            and not isinstance(row.get("observedDurationSeconds"), bool)
        ),
    }
    if coverage != derived_coverage:
        errors.append(f"{label}.observedCoverage: not the exact re-derived aggregate")
    required_coverage = {
        "portIds": set(case_record.get("requiredPortIds", [])),
        "operationIds": set(case_record.get("requiredOperationIds", [])),
        "transitionIds": set(case_record.get("requiredTransitionIds", [])),
        "faultClasses": set(case_record.get("requiredFaultClasses", [])),
        "artifactSchemaRefs": set(case_record.get("requiredArtifactSchemaRefs", [])),
        "oracleClasses": set(case_record.get("requiredOracleClasses", [])),
        "assertionDigests": {
            item.get("assertionDigest")
            for item in case_record.get("assertions", [])
            if isinstance(item, Mapping)
        },
    }
    for field, required in required_coverage.items():
        observed = set(derived_coverage[field])
        missing = required - observed
        if missing:
            errors.append(f"{label}.observedCoverage.{field}: missing {sorted(missing)}")
    minimum_repeat = case_record.get("minimumRepeat")
    for fault in required_coverage["faultClasses"]:
        if not isinstance(minimum_repeat, int) or fault_repeats.get(fault, 0) < minimum_repeat:
            errors.append(
                f"{label}.observedCoverage.repeatByFaultClass: {fault!r} has "
                f"{fault_repeats.get(fault, 0)}, requires {minimum_repeat!r}"
            )
    minimum_duration = case_record.get("minimumDurationSeconds")
    if not isinstance(minimum_duration, int) or derived_coverage[
        "totalObservedDurationSeconds"
    ] < minimum_duration:
        errors.append(
            f"{label}.observedCoverage.totalObservedDurationSeconds: below Case "
            f"minimum {minimum_duration!r}"
        )

    dependencies = completion.get("dependencyCompletionDigests")
    dependency_ids = [
        item.get("caseId")
        for item in dependencies
        if isinstance(item, Mapping)
    ] if isinstance(dependencies, list) else []
    if dependency_ids != sorted(dependency_ids, key=canonical_json_bytes) or len(
        dependency_ids
    ) != len(set(dependency_ids)):
        errors.append(
            f"{label}.dependencyCompletionDigests: must be unique and sorted by caseId"
        )
    required_dependencies = set(
        classification.get("dependsOnCaseIds", [])
        if isinstance(classification, Mapping)
        else []
    )
    if set(dependency_ids) != required_dependencies:
        errors.append(
            f"{label}.dependencyCompletionDigests: must exactly equal Case dependencies "
            f"{sorted(required_dependencies)}"
        )
    _case_completion_evaluator_matches(
        completion.get("evaluator"),
        scenario_bundles,
        completion,
        code_git,
        evidence_git,
        root,
        mapping,
        case_registry,
        trust,
        label,
        errors,
    )
    completed_at = _parse_time(completion.get("completedAt"), f"{label}.completedAt", errors)
    evaluator_manifest = completion.get("evaluator")
    evaluator_manifest_descriptor = (
        evaluator_manifest.get("toolManifest")
        if isinstance(evaluator_manifest, Mapping)
        else None
    )
    if isinstance(evaluator_manifest_descriptor, Mapping) and evidence_git is not None:
        evaluator_manifest_blob = evidence_git.blob(
            evaluator_manifest_descriptor.get("path"),
            f"{label}.evaluator.toolManifest.path",
            errors,
        )
        parsed_evaluator_manifest = (
            _load_json_bytes(
                evaluator_manifest_blob,
                f"{label}.evaluator.toolManifest",
                errors,
            )
            if evaluator_manifest_blob is not None
            else None
        )
        evaluator_created = (
            _parse_time(
                parsed_evaluator_manifest.get("createdAt"),
                f"{label}.evaluator.toolManifest.createdAt",
                errors,
            )
            if isinstance(parsed_evaluator_manifest, Mapping)
            else None
        )
        if (
            completed_at is not None
            and evaluator_created is not None
            and evaluator_created >= completed_at
        ):
            errors.append(
                f"{label}.completedAt: must strictly follow evaluator tool manifest"
            )
    indexes = [
        item["index"]
        for item in scenario_bundles
        if isinstance(item.get("index"), Mapping)
    ]
    for number, index in enumerate(indexes):
        created = _parse_time(index.get("createdAt"), f"{label}.index[{number}].createdAt", errors)
        if completed_at is not None and created is not None and completed_at < created:
            errors.append(f"{label}.completedAt: predates aggregated signed index")
    return {
        "descriptor": descriptor,
        "completion": completion,
        "case": case_record,
        "platformProfileId": signed_platform_id,
        "platformProfileDigest": completion.get("platformProfileDigest"),
        "backendProfileDigest": completion.get("backendProfileDigest"),
        "exactQualificationKey": exact_qualification_key,
        "scenarioRows": derived_rows,
        "scenarioBundles": scenario_bundles,
        "scenarioIdentities": scenario_identities,
        "rawHashes": raw_hashes,
        "runnerRawHashes": runner_raw_hashes,
        "coreDigests": core_digests,
        "indexDigests": index_digests,
        "runnerDigests": runner_digests,
        "completedAt": completed_at,
    }


def _validate_case_completion_set(
    bundles: Sequence[Mapping[str, Any]], label: str, errors: list[str]
) -> None:
    """Validate dependency resolution and forbid cross-Case/platform evidence reuse."""

    by_case_platform: dict[tuple[Any, ...], Mapping[str, Any]] = {}
    completion_digests: dict[Any, tuple[Any, ...]] = {}
    reused: dict[tuple[str, Any], tuple[Any, ...]] = {}
    for bundle in bundles:
        completion = bundle.get("completion")
        if not isinstance(completion, Mapping):
            continue
        identity = (
            completion.get("platformProfileId"),
            completion.get("platformProfileDigest"),
            completion.get("backendProfileDigest"),
            completion.get("exactQualificationKey"),
            completion.get("caseId"),
        )
        if identity in by_case_platform:
            errors.append(
                f"{label}: duplicate completion for signed owner/Case {identity!r}"
            )
        by_case_platform[identity] = bundle
        digest = completion.get("completionDigest")
        previous = completion_digests.get(digest)
        if previous is not None and previous != identity:
            errors.append(f"{label}: completionDigest reused across {previous!r} and {identity!r}")
        completion_digests[digest] = identity
        for category in (
            "scenarioIdentities",
            "rawHashes",
            "runnerRawHashes",
            "coreDigests",
            "indexDigests",
            "runnerDigests",
        ):
            for value in bundle.get(category, set()):
                key = (category, value)
                previous_identity = reused.get(key)
                if previous_identity is not None and previous_identity != identity:
                    errors.append(
                        f"{label}: {category} evidence {value!r} reused across "
                        f"{previous_identity!r} and {identity!r}"
                    )
                reused[key] = identity

    visiting: set[tuple[Any, ...]] = set()
    visited: set[tuple[Any, ...]] = set()

    def visit(
        identity: tuple[Any, ...], path: list[tuple[Any, ...]]
    ) -> None:
        if identity in visiting:
            errors.append(f"{label}: completion dependency cycle {path + [identity]!r}")
            return
        if identity in visited:
            return
        visiting.add(identity)
        bundle = by_case_platform.get(identity)
        completion = bundle.get("completion") if isinstance(bundle, Mapping) else None
        dependencies = (
            completion.get("dependencyCompletionDigests", [])
            if isinstance(completion, Mapping)
            else []
        )
        for dependency in dependencies:
            if not isinstance(dependency, Mapping):
                continue
            dependency_identity = (*identity[:4], dependency.get("caseId"))
            dependency_bundle = by_case_platform.get(dependency_identity)
            if dependency_bundle is None:
                errors.append(
                    f"{label}: {identity!r} lacks same signed-owner dependency "
                    f"{dependency_identity!r}"
                )
                continue
            dependency_completion = dependency_bundle.get("completion")
            if not isinstance(dependency_completion, Mapping) or dependency.get(
                "completionDigest"
            ) != dependency_completion.get("completionDigest"):
                errors.append(
                    f"{label}: {identity!r} dependency digest does not resolve "
                    f"{dependency_identity!r}"
                )
            completed_at = bundle.get("completedAt") if isinstance(bundle, Mapping) else None
            dependency_at = dependency_bundle.get("completedAt")
            if (
                isinstance(completed_at, _datetime.datetime)
                and isinstance(dependency_at, _datetime.datetime)
                and dependency_at >= completed_at
            ):
                errors.append(
                    f"{label}: dependency {dependency_identity!r} completed after consumer"
                )
            visit(dependency_identity, path + [identity])
        visiting.remove(identity)
        visited.add(identity)

    for identity in by_case_platform:
        visit(identity, [])


def _validate_e4_completion_subject_groups(
    bundles: Sequence[Mapping[str, Any]],
    *,
    case_registry: Mapping[str, Any] | None,
    trust: _TrustContext | None,
    root: Path,
    code_git: _GitView | None,
    evidence_git: _GitView | None,
    mapping: Mapping[str, Any] | None,
    label: str,
    errors: list[str],
) -> None:
    """Validate complete E4 Subject groups when no QualificationRecord exists."""

    groups: dict[tuple[Any, ...], list[Mapping[str, Any]]] = {}
    for bundle in bundles:
        completion = bundle.get("completion")
        if not isinstance(completion, Mapping) or completion.get(
            "evidenceGrade"
        ) != "E4-PHYSICAL-QUALIFICATION":
            continue
        owner = (
            completion.get("platformProfileId"),
            completion.get("platformProfileDigest"),
            completion.get("backendProfileDigest"),
            completion.get("exactQualificationKey"),
        )
        groups.setdefault(owner, []).append(bundle)
    for owner, completion_group in groups.items():
        scenario_bundles = [
            scenario_bundle
            for completion_bundle in completion_group
            for scenario_bundle in completion_bundle.get("scenarioBundles", [])
            if isinstance(scenario_bundle, Mapping)
        ]
        subjects = [item.get("subject") for item in scenario_bundles]
        if not subjects or not all(isinstance(item, Mapping) for item in subjects):
            errors.append(f"{label}.E4[{owner!r}]: complete signed Subject is missing")
            continue
        subject = subjects[0]
        assert isinstance(subject, Mapping)
        indexes = [
            item.get("index")
            for item in scenario_bundles
            if isinstance(item.get("index"), Mapping)
        ]
        created_values = [
            item.get("createdAt")
            for item in indexes
            if isinstance(item, Mapping) and isinstance(item.get("createdAt"), str)
        ]
        synthetic_record = {
            "qualificationRecordId": subject.get("qualificationRecordId"),
            "qualificationSubjectManifestDigest": subject.get("manifestDigest"),
            "platformProfileHash": owner[1],
            "qualificationCaseMatrixSha256": subject.get(
                "qualificationCaseMatrixSha256"
            ),
            "pciIdentityMatch": subject.get("pciIdentityMatch"),
            "deviceArchetype": subject.get("deviceArchetype"),
            "deviceTraits": subject.get("deviceTraits"),
            "deviceFirmwareAndRom": subject.get("deviceFirmwareAndRom"),
            "kernelQemuFirmwareBackend": subject.get(
                "kernelQemuFirmwareBackend"
            ),
            "iommuInterruptResetProviders": subject.get(
                "iommuInterruptResetProviders"
            ),
            "guestDriverAndWorkload": subject.get("guestDriverAndWorkload"),
            "caseIds": subject.get("caseIds"),
            "exactQualificationKey": owner[3],
            "e4EvidenceHashes": _canonical_string_union(
                [
                    subject.get("manifestDigest"),
                    *(
                        item.get("indexDigest")
                        for item in indexes
                        if isinstance(item, Mapping)
                    ),
                ]
            ),
            "issuedAt": (
                max(created_values)
                if created_values
                else subject.get("issuedAt")
            ),
        }
        _validate_qualification_subject_manifest(
            synthetic_record,
            scenario_bundles,
            case_registry,
            trust,
            root,
            code_git,
            evidence_git,
            mapping,
            f"{label}.E4[{owner!r}]",
            errors,
        )


QUALIFICATION_INDEX_FIELDS = {
    "schemaVersion",
    "indexId",
    "canonicalProfileId",
    "targetCodeRevision",
    "mappingCore",
    "qualificationCaseMatrixSha256",
    "platformProfileIds",
    "supportedCatalog",
    "catalogRollbackAnchor",
    "qualificationRecords",
    "e4CaseCompletionRecords",
    "qualificationCoverage",
    "issuedAt",
    "keyRingVersion",
    "signerKeyId",
    "indexDigest",
    "signature",
}
QUALIFICATION_TARGET_CODE_FIELDS = {"repositoryId", "objectFormat", "revision"}
QUALIFICATION_MAPPING_CORE_FIELDS = {"mappingCoreId", "mappingCoreDigest"}
QUALIFICATION_SUPPORTED_CATALOG_ARTIFACT_FIELDS = {
    "path",
    "sha256",
    "schemaRef",
    "schemaSha256",
    "catalogId",
    "catalogSequence",
    "catalogDigest",
}
QUALIFICATION_RECORD_ARTIFACT_FIELDS = {
    "path",
    "sha256",
    "schemaRef",
    "schemaSha256",
    "qualificationRecordDigest",
    "platformProfileId",
}
E4_CASE_COMPLETION_FIELDS = {
    "path",
    "sha256",
    "schemaRef",
    "schemaSha256",
    "caseId",
    "platformProfileId",
    "targetRepositoryCommit",
    "mappingCoreId",
    "evidenceGrade",
    "exactQualificationKey",
    "completionDigest",
    "qualificationRecordDigests",
}
# Retained only so the unreachable legacy validator remains importable while the
# public validator below consumes the final CaseCompletionRecord wire shape.
E4_RESULT_FIELDS = E4_CASE_COMPLETION_FIELDS
QUALIFICATION_COVERAGE_FIELDS = {
    "qualificationRecordDigest",
    "platformProfileId",
    "derivedCaseIds",
    "caseEvidenceBindings",
}
CASE_EVIDENCE_BINDING_FIELDS = {
    "caseId",
    "e4CaseCompletionSha256",
    "e4CaseCompletionDigest",
}
QUALIFICATION_ANCHOR_BINDING_FIELDS = {
    "snapshot",
    "recordState",
    "catalogId",
    "minimumCatalogSequence",
    "acceptedCatalogDigest",
    "anchorVersion",
    "resourceVersion",
    "authorityId",
    "anchorDigest",
    "receipt",
}
QUALIFICATION_ANCHOR_RECEIPT_FIELDS = {
    "receiptId",
    "subjectAnchorDigest",
    "catalogId",
    "minimumCatalogSequence",
    "acceptedCatalogDigest",
    "anchorVersion",
    "resourceVersion",
    "authorityId",
    "issuedAt",
    "trustRootDigest",
    "receiptDigest",
}
QUALIFICATION_RECORD_FIELDS = {
    "schemaVersion",
    "qualificationRecordId",
    "qualificationSubjectManifestDigest",
    "exactQualificationKey",
    "platformProfileHash",
    "pciIdentityMatch",
    "deviceArchetype",
    "deviceTraits",
    "qualificationCaseMatrixSha256",
    "deviceFirmwareAndRom",
    "kernelQemuFirmwareBackend",
    "iommuInterruptResetProviders",
    "guestDriverAndWorkload",
    "caseIds",
    "e4EvidenceHashes",
    "issuedAt",
    "notBefore",
    "expiresAt",
    "qualificationSignerKeyId",
    "keyRingVersion",
    "signature",
    "recordDigest",
}
PCI_IDENTITY_FIELDS = {
    "vendorId",
    "deviceId",
    "subsystemVendorId",
    "subsystemDeviceId",
    "revisionId",
    "classCode",
    "functionRoleAlgorithm",
    "functionRoleAlgorithmVersion",
    "functionRoleDefinitionDigest",
    "functionRole",
    "identityVariant",
    "identityProviderId",
    "identityProviderVersion",
    "identityProviderDefinitionDigest",
    "identityVectorSetDigest",
    "serialValueHashOrNull",
    "physicalPathOrNull",
    "vendorExtractorIdOrNull",
    "vendorExtractorDefinitionDigestOrNull",
    "errataProfileId",
}
DEVICE_FIRMWARE_FIELDS = {
    "deviceFirmwareVersion",
    "deviceFirmwareDigest",
    "optionRomDigestOrNull",
    "vpdDigestOrNull",
    "settingsDigest",
}
PLATFORM_RUNTIME_FIELDS = {
    "platformProfileId",
    "osRelease",
    "architecture",
    "kernelRelease",
    "kernelBuildDigest",
    "qemuVersion",
    "qemuBinaryDigest",
    "machineType",
    "machineVersion",
    "firmwareKind",
    "firmwareCodeDigest",
    "firmwareVarsBaseDigestOrNull",
    "backendFamily",
    "configuredIommuType",
}
PROVIDER_FIELDS = {
    "iommuProviderId",
    "iommuProviderDigest",
    "interruptRemappingProviderId",
    "interruptRemappingProviderDigest",
    "physicalIsolationProviderId",
    "physicalIsolationProviderDigest",
    "resetProviderId",
    "resetProviderDigest",
    "dmaIrqObserverId",
    "dmaIrqObserverDigest",
}
GUEST_WORKLOAD_FIELDS = {
    "guestAbiClass",
    "guestOs",
    "guestKernel",
    "guestDriverName",
    "guestDriverVersion",
    "guestDriverDigest",
    "workloadId",
    "workloadDefinitionDigest",
    "minimumDurationSeconds",
}
SUPPORTED_CATALOG_FIELDS = {
    "schemaVersion",
    "catalogId",
    "catalogSequence",
    "previousCatalogDigest",
    "minimumReaderSchemaVersion",
    "qualificationRecordDigests",
    "denyAndRevocationEntries",
    "revocationBehavior",
    "issuedAt",
    "notBefore",
    "expiresAt",
    "keyRingVersion",
    "productReleaseSignerKeyId",
    "signature",
    "catalogDigest",
}
DENY_ENTRY_FIELDS = {
    "entryId",
    "selectorKind",
    "selectorDigest",
    "reasonCode",
    "severity",
    "revocationBehavior",
    "effectiveAt",
    "evidenceHash",
}
CATALOG_ANCHOR_FIELDS = {
    "schemaVersion",
    "recordType",
    "canonicalProfileId",
    "recordState",
    "catalogId",
    "anchorVersion",
    "resourceVersion",
    "minimumCatalogSequence",
    "acceptedCatalogDigest",
    "updatedAt",
    "authorityId",
    "previousAnchorDigestOrNull",
    "casPrecondition",
    "anchorDigest",
    "receipt",
}
CATALOG_ANCHOR_CAS_FIELDS = {
    "expectedAnchorVersionOrNull",
    "expectedResourceVersionOrNull",
    "expectedMinimumCatalogSequenceOrNull",
    "expectedAcceptedCatalogDigestOrNull",
    "expectedAnchorDigestOrNull",
}
CATALOG_ANCHOR_RECEIPT_FIELDS = {
    "schemaVersion",
    "receiptId",
    "subjectAnchorDigest",
    "catalogId",
    "minimumCatalogSequence",
    "acceptedCatalogDigest",
    "anchorVersion",
    "resourceVersion",
    "authorityId",
    "issuedAt",
    "trustRootDigest",
    "receiptDigest",
    "rootSignatures",
}
CATALOG_ANCHOR_ROOT_SIGNATURE_FIELDS = {
    "rootKeyId",
    "signedAt",
    "algorithm",
    "signature",
}
QUALIFICATION_MATRIX_FIELDS = {
    "matrixVersion",
    "derivationMode",
    "missingRule",
    "evidenceRule",
    "globalMandatoryCaseIds",
    "platformRules",
    "backendRules",
    "machineFirmwareRules",
    "configuredIommuTypeRules",
    "identityVariantRules",
    "deviceArchetypeRules",
    "deviceTraitRules",
    "derivationRule",
}


def _validate_recursive_digest_fields(value: Any, label: str, errors: list[str]) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            child = f"{label}.{key}"
            if key.endswith("Digest") or key.endswith("Hash"):
                if item is None and key.endswith("OrNull"):
                    continue
                _is_digest(item, child, errors, nonzero=True)
            else:
                _validate_recursive_digest_fields(item, child, errors)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _validate_recursive_digest_fields(item, f"{label}[{index}]", errors)


def _validate_matrix_rule_list(
    value: Any,
    selector_fields: tuple[str, ...],
    *,
    extra_fields: set[str],
    known_cases: set[str],
    label: str,
    errors: list[str],
) -> dict[tuple[str, ...], Mapping[str, Any]]:
    if not isinstance(value, list) or not value:
        errors.append(f"{label}: expected non-empty closed rule array")
        return {}
    result: dict[tuple[str, ...], Mapping[str, Any]] = {}
    order: list[bytes] = []
    for index, rule in enumerate(value):
        rule_label = f"{label}[{index}]"
        _exact_keys(
            rule,
            {*selector_fields, "caseIds", *extra_fields},
            rule_label,
            errors,
        )
        if not isinstance(rule, Mapping):
            continue
        selector: list[str] = []
        valid_selector = True
        for field in selector_fields:
            item = rule.get(field)
            if not isinstance(item, str) or not item:
                errors.append(f"{rule_label}.{field}: expected non-empty selector")
                valid_selector = False
            else:
                selector.append(item)
        cases = _unique_strings(rule.get("caseIds"), f"{rule_label}.caseIds", errors)
        _require_canonical_set_order(rule.get("caseIds"), f"{rule_label}.caseIds", errors)
        unknown_cases = sorted(set(cases) - known_cases)
        if unknown_cases:
            errors.append(f"{rule_label}.caseIds: unknown closed Case IDs {unknown_cases}")
        if "requiredDeviceTraits" in extra_fields:
            traits = _unique_strings(
                rule.get("requiredDeviceTraits"),
                f"{rule_label}.requiredDeviceTraits",
                errors,
            )
            _require_canonical_set_order(
                rule.get("requiredDeviceTraits"),
                f"{rule_label}.requiredDeviceTraits",
                errors,
            )
            if not traits:
                errors.append(f"{rule_label}.requiredDeviceTraits: must not be empty")
        if not valid_selector:
            continue
        selector_key = tuple(selector)
        if selector_key in result:
            errors.append(f"{rule_label}: duplicate selector {selector_key!r}")
        else:
            result[selector_key] = rule
        try:
            order.append(canonical_json_bytes(list(selector_key)))
        except (CanonicalizationError, TypeError, ValueError) as exc:
            errors.append(f"{rule_label}: invalid canonical selector: {exc}")
    if order != sorted(order) or len(order) != len(set(order)):
        errors.append(f"{label}: rules must be unique and sorted by canonical selector bytes")
    return result


def _validate_qualification_case_matrix(
    matrix: Any,
    policy: Mapping[str, Any] | None,
    known_cases: set[str],
    errors: list[str],
) -> dict[str, Any] | None:
    label = "compatibility policy.qualificationCaseMatrix"
    _exact_keys(matrix, QUALIFICATION_MATRIX_FIELDS, label, errors)
    if not isinstance(matrix, Mapping):
        return None
    expected_literals = {
        "matrixVersion": 1,
        "derivationMode": "EXACT_UNION",
        "missingRule": "DENY_QUALIFIED",
        "evidenceRule": "E4_EXACT_CASE_SET",
    }
    for field, expected in expected_literals.items():
        if matrix.get(field) != expected:
            errors.append(f"{label}.{field}: expected {expected!r}")
    if not isinstance(matrix.get("derivationRule"), str) or not matrix.get("derivationRule"):
        errors.append(f"{label}.derivationRule: expected non-empty normative rule")
    global_cases = _unique_strings(
        matrix.get("globalMandatoryCaseIds"), f"{label}.globalMandatoryCaseIds", errors
    )
    _require_canonical_set_order(
        matrix.get("globalMandatoryCaseIds"), f"{label}.globalMandatoryCaseIds", errors
    )
    unknown_global = sorted(set(global_cases) - known_cases)
    if unknown_global:
        errors.append(f"{label}.globalMandatoryCaseIds: unknown Case IDs {unknown_global}")

    specifications = {
        "platform": ("platformRules", ("platformProfileId",), set()),
        "backend": ("backendRules", ("backendFamily",), set()),
        "machine_firmware": (
            "machineFirmwareRules",
            ("machine", "firmware"),
            set(),
        ),
        "iommu": (
            "configuredIommuTypeRules",
            ("configuredIommuType",),
            set(),
        ),
        "identity": ("identityVariantRules", ("identityVariant",), set()),
        "archetype": (
            "deviceArchetypeRules",
            ("deviceArchetype",),
            {"requiredDeviceTraits"},
        ),
        "trait": ("deviceTraitRules", ("deviceTrait",), set()),
    }
    rules: dict[str, dict[tuple[str, ...], Mapping[str, Any]]] = {}
    for result_key, (field, selectors, extras) in specifications.items():
        rules[result_key] = _validate_matrix_rule_list(
            matrix.get(field),
            selectors,
            extra_fields=extras,
            known_cases=known_cases,
            label=f"{label}.{field}",
            errors=errors,
        )

    platforms = [item for item in policy.get("platforms", []) if isinstance(item, Mapping)]
    expected_platforms = {
        (item.get("id"),)
        for item in platforms
        if isinstance(item.get("id"), str) and item.get("id")
    }
    if set(rules["platform"]) != expected_platforms:
        errors.append(f"{label}.platformRules: must exactly cover policy platforms")
    backend_policy = policy.get("backendPolicy")
    expected_backends: set[tuple[str, ...]] = set()
    expected_iommu_types: set[tuple[str, ...]] = set()
    if isinstance(backend_policy, Mapping):
        current = backend_policy.get("currentProductFamily")
        if isinstance(current, str):
            expected_backends.add((current,))
        for backend in backend_policy.get("futureFamilies", []):
            if isinstance(backend, str):
                expected_backends.add((backend,))
        for iommu_type in backend_policy.get("allowedConfiguredTypes", []):
            if isinstance(iommu_type, str):
                expected_iommu_types.add((iommu_type,))
        if ("VFIO_CDEV_IOMMUFD",) in expected_backends:
            expected_iommu_types.add(("IOMMUFD_IOAS",))
    if set(rules["backend"]) != expected_backends:
        errors.append(f"{label}.backendRules: must exactly cover current/future backend policy")
    if set(rules["iommu"]) != expected_iommu_types:
        errors.append(
            f"{label}.configuredIommuTypeRules: must exactly cover configured IOMMU types"
        )
    expected_machine_firmware = {
        (item.get("machine"), item.get("firmware"))
        for platform in platforms
        for item in platform.get("machineFirmware", [])
        if isinstance(item, Mapping)
        and isinstance(item.get("machine"), str)
        and isinstance(item.get("firmware"), str)
    }
    if set(rules["machine_firmware"]) != expected_machine_firmware:
        errors.append(
            f"{label}.machineFirmwareRules: must exactly cover policy machine/firmware union"
        )
    if set(rules["identity"]) != {("SLOT_BOUND",), ("STRONG_SERIAL",)}:
        errors.append(f"{label}.identityVariantRules: must exactly cover both variants")
    hcl_policy = policy.get("hclPolicy")
    hcl_items = hcl_policy.get("archetypes", []) if isinstance(hcl_policy, Mapping) else []
    hcl_archetypes = {
        item.get("id"): set(item.get("requiredTraitCoverage", []))
        for item in hcl_items
        if isinstance(item, Mapping)
        and isinstance(item.get("id"), str)
    }
    expected_archetypes = {(item,) for item in {*hcl_archetypes, "GENERIC_PCI"}}
    if set(rules["archetype"]) != expected_archetypes:
        errors.append(
            f"{label}.deviceArchetypeRules: must exactly cover HCL archetypes plus GENERIC_PCI"
        )
    trait_selectors = {selector[0] for selector in rules["trait"]}
    for selector, rule in rules["archetype"].items():
        required_traits = set(rule.get("requiredDeviceTraits", []))
        if not required_traits.issubset(trait_selectors):
            errors.append(
                f"{label}.deviceArchetypeRules[{selector[0]}]: required traits lack exact trait rules"
            )
        hcl_required = hcl_archetypes.get(selector[0], set())
        if not hcl_required.issubset(required_traits):
            errors.append(
                f"{label}.deviceArchetypeRules[{selector[0]}]: weakens HCL required traits "
                f"{sorted(hcl_required - required_traits)}"
            )
    matrix_digest = _canonical_digest(matrix, f"{label} canonical bytes", errors)
    if matrix_digest is None:
        return None
    return {
        "digest": matrix_digest,
        "global": set(global_cases),
        **rules,
    }


def _validate_qualification_record(
    record: Any,
    platform_by_id: Mapping[str, Mapping[str, Any]],
    policy: Mapping[str, Any],
    matrix_info: Mapping[str, Any] | None,
    known_cases: set[str],
    e4_hashes: set[str],
    index_issued_at: _datetime.datetime | None,
    trust: _TrustContext | None,
    label: str,
    errors: list[str],
) -> tuple[str | None, str | None, tuple[str, str] | None]:
    _exact_keys(record, QUALIFICATION_RECORD_FIELDS, label, errors)
    if not isinstance(record, Mapping):
        return None, None, None
    policy_mapping: Mapping[str, Any] = policy if isinstance(policy, Mapping) else {}
    if record.get("schemaVersion") != 1:
        errors.append(f"{label}.schemaVersion: expected 1")
    nested_shapes = (
        ("pciIdentityMatch", PCI_IDENTITY_FIELDS),
        ("deviceFirmwareAndRom", DEVICE_FIRMWARE_FIELDS),
        ("kernelQemuFirmwareBackend", PLATFORM_RUNTIME_FIELDS),
        ("iommuInterruptResetProviders", PROVIDER_FIELDS),
        ("guestDriverAndWorkload", GUEST_WORKLOAD_FIELDS),
    )
    for field, fields in nested_shapes:
        _exact_keys(record.get(field), fields, f"{label}.{field}", errors)
    _validate_recursive_digest_fields(record, label, errors)
    _nonempty_string(record.get("qualificationRecordId"), f"{label}.qualificationRecordId", errors)
    if record.get("deviceArchetype") not in {
        "CONSUMER_GPU",
        "PROFESSIONAL_GPU",
        "HBA",
        "ACCELERATOR",
        "GENERIC_PCI",
    }:
        errors.append(f"{label}.deviceArchetype: unknown closed archetype")
    _positive_safe_integer(record.get("keyRingVersion"), f"{label}.keyRingVersion", errors)
    _nonempty_string(
        record.get("qualificationSignerKeyId"),
        f"{label}.qualificationSignerKeyId",
        errors,
    )
    _is_digest(
        record.get("qualificationCaseMatrixSha256"),
        f"{label}.qualificationCaseMatrixSha256",
        errors,
        nonzero=True,
    )
    for field in ("deviceTraits", "caseIds", "e4EvidenceHashes"):
        values = _unique_strings(record.get(field), f"{label}.{field}", errors)
        _require_canonical_set_order(record.get(field), f"{label}.{field}", errors)
        if field == "caseIds":
            malformed = [
                case_id
                for case_id in values
                if re.fullmatch(r"(?:C|O|S|D|M|F)[0-9]{2}[a-z]?", case_id) is None
            ]
            if malformed:
                errors.append(f"{label}.caseIds: malformed closed Case IDs {malformed}")
            unknown = sorted(set(values) - known_cases)
            if unknown:
                errors.append(f"{label}.caseIds: unknown Case IDs {unknown}")
        if field == "e4EvidenceHashes":
            for digest in values:
                _is_digest(digest, f"{label}.e4EvidenceHashes", errors, nonzero=True)
            missing = sorted(set(values) - e4_hashes)
            if missing:
                errors.append(f"{label}.e4EvidenceHashes: not present in release E4 results {missing}")
    firmware = record.get("deviceFirmwareAndRom")
    if isinstance(firmware, Mapping):
        _nonempty_string(
            firmware.get("deviceFirmwareVersion"),
            f"{label}.deviceFirmwareAndRom.deviceFirmwareVersion",
            errors,
        )
        for field in ("deviceFirmwareDigest", "settingsDigest"):
            _is_digest(
                firmware.get(field),
                f"{label}.deviceFirmwareAndRom.{field}",
                errors,
                nonzero=True,
            )
        for field in ("optionRomDigestOrNull", "vpdDigestOrNull"):
            _nullable_digest(
                firmware.get(field),
                f"{label}.deviceFirmwareAndRom.{field}",
                errors,
                nonzero=True,
            )
    providers = record.get("iommuInterruptResetProviders")
    if isinstance(providers, Mapping):
        for field in (
            "iommuProviderId",
            "interruptRemappingProviderId",
            "physicalIsolationProviderId",
            "resetProviderId",
            "dmaIrqObserverId",
        ):
            _nonempty_string(providers.get(field), f"{label}.iommuInterruptResetProviders.{field}", errors)
        for field in (
            "iommuProviderDigest",
            "interruptRemappingProviderDigest",
            "physicalIsolationProviderDigest",
            "resetProviderDigest",
            "dmaIrqObserverDigest",
        ):
            _is_digest(
                providers.get(field),
                f"{label}.iommuInterruptResetProviders.{field}",
                errors,
                nonzero=True,
            )
    workload = record.get("guestDriverAndWorkload")
    if isinstance(workload, Mapping):
        for field in (
            "guestAbiClass",
            "guestOs",
            "guestKernel",
            "guestDriverName",
            "guestDriverVersion",
            "workloadId",
        ):
            _nonempty_string(workload.get(field), f"{label}.guestDriverAndWorkload.{field}", errors)
        for field in ("guestDriverDigest", "workloadDefinitionDigest"):
            _is_digest(
                workload.get(field),
                f"{label}.guestDriverAndWorkload.{field}",
                errors,
                nonzero=True,
            )
        _positive_safe_integer(
            workload.get("minimumDurationSeconds"),
            f"{label}.guestDriverAndWorkload.minimumDurationSeconds",
            errors,
        )
    exact_key_projection = {
        field: copy.deepcopy(record.get(field))
        for field in (
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
    actual_exact_key = _canonical_digest(exact_key_projection, f"{label}.exactQualificationKey projection", errors)
    if actual_exact_key is not None and record.get("exactQualificationKey") != actual_exact_key:
        errors.append(
            f"{label}.exactQualificationKey: declared {record.get('exactQualificationKey')}, actual {actual_exact_key}"
        )
    issued = _parse_time(record.get("issuedAt"), f"{label}.issuedAt", errors)
    not_before = _parse_time(record.get("notBefore"), f"{label}.notBefore", errors)
    expires = _parse_time(record.get("expiresAt"), f"{label}.expiresAt", errors)
    if issued is not None and not_before is not None and issued > not_before:
        errors.append(f"{label}: issuedAt must not follow notBefore")
    if not_before is not None and expires is not None and not_before >= expires:
        errors.append(f"{label}: notBefore must precede expiresAt")
    if index_issued_at is not None and not_before is not None and expires is not None:
        if not (not_before <= index_issued_at < expires):
            errors.append(f"{label}: record is not valid at qualification index issuedAt")
    identity = record.get("pciIdentityMatch")
    if isinstance(identity, Mapping):
        _nonempty_string(
            identity.get("errataProfileId"),
            f"{label}.pciIdentityMatch.errataProfileId",
            errors,
        )
        for field in ("vendorId", "deviceId", "subsystemVendorId", "subsystemDeviceId"):
            value = identity.get(field)
            if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{4}", value) is None:
                errors.append(f"{label}.pciIdentityMatch.{field}: expected four lowercase hex digits without 0x")
        revision = identity.get("revisionId")
        if not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{2}", revision) is None:
            errors.append(f"{label}.pciIdentityMatch.revisionId: expected two lowercase hex digits without 0x")
        class_code = identity.get("classCode")
        if not isinstance(class_code, str) or re.fullmatch(r"[0-9a-f]{6}", class_code) is None:
            errors.append(f"{label}.pciIdentityMatch.classCode: expected six lowercase hex digits")
        role_by_class = {
            "00": "UNCLASSIFIED",
            "01": "MASS_STORAGE_CONTROLLER",
            "02": "NETWORK_CONTROLLER",
            "03": "DISPLAY_CONTROLLER",
            "04": "MULTIMEDIA_CONTROLLER",
            "05": "MEMORY_CONTROLLER",
            "06": "BRIDGE_DEVICE",
            "07": "SIMPLE_COMMUNICATION_CONTROLLER",
            "08": "BASE_SYSTEM_PERIPHERAL",
            "09": "INPUT_DEVICE_CONTROLLER",
            "0a": "DOCKING_STATION",
            "0b": "PROCESSOR",
            "0c": "SERIAL_BUS_CONTROLLER",
            "0d": "WIRELESS_CONTROLLER",
            "0e": "INTELLIGENT_CONTROLLER",
            "0f": "SATELLITE_COMMUNICATION_CONTROLLER",
            "10": "ENCRYPTION_CONTROLLER",
            "11": "SIGNAL_PROCESSING_CONTROLLER",
            "12": "PROCESSING_ACCELERATOR",
            "13": "NON_ESSENTIAL_INSTRUMENTATION",
            "40": "COPROCESSOR",
        }
        expected_role = (
            role_by_class.get(class_code[:2], "RESERVED_OR_VENDOR_SPECIFIC")
            if isinstance(class_code, str) and len(class_code) == 6
            else None
        )
        if expected_role is not None and identity.get("functionRole") != expected_role:
            errors.append(
                f"{label}.pciIdentityMatch.functionRole: classCode requires {expected_role}"
            )
        expected_identity_literals = {
            "functionRoleAlgorithm": "CLASS_CODE_ROLE_V1",
            "functionRoleAlgorithmVersion": 1,
            "functionRoleDefinitionDigest": "sha256:7f119749c919c48f6d9cae971378e78ab3ac39ce404d9f2651bc6766812ff35f",
            "identityProviderVersion": 1,
            "identityVectorSetDigest": "sha256:0d24bf773afc921caa8965b69588cbfb5876e6c636c283b3ff3362507b9ee693",
        }
        for field, expected in expected_identity_literals.items():
            if identity.get(field) != expected:
                errors.append(f"{label}.pciIdentityMatch.{field}: expected {expected!r}")
        provider_definitions = {
            "PCI_DSN_EUI64_V1": "sha256:c477361654ccb4f6c1b61446d3e9695bf666a0e5cf313b18789a76d2d340cd65",
            "PCI_VPD_SN_UTF8_V1": "sha256:2ac49a541d5e0324d1f8eaacbcfb87ad8667fe3e86599936a751cb74d9769429",
            "VENDOR_QUALIFIED_BYTES_V1": "sha256:084e4ef848c737fe0db24231bdda1441c40287cd99743c61ce2e340644c23764",
            "ACPI_FIRMWARE_PATH_V1": "sha256:61b92f14fcd158f7885ec07d0a375324e051e3b2f936c748ac103b4a230203e4",
            "SMBIOS_SYSTEM_SLOT_V1": "sha256:c8a3291773b34ff8ef67511a5574db43be24b07bd7840c900bbbdab682687b0d",
            "DEVICETREE_FULL_PATH_V1": "sha256:6165a1a4c882e22bc2011448b956fb70967fdc146189c4c66664ae4b994577d6",
        }
        provider = identity.get("identityProviderId")
        if provider not in provider_definitions:
            errors.append(f"{label}.pciIdentityMatch.identityProviderId: unknown provider")
        elif identity.get("identityProviderDefinitionDigest") != provider_definitions[provider]:
            errors.append(
                f"{label}.pciIdentityMatch.identityProviderDefinitionDigest: "
                "does not bind the closed provider definition"
            )
        variant = identity.get("identityVariant")
        serial_hash = identity.get("serialValueHashOrNull")
        physical_path = identity.get("physicalPathOrNull")
        if isinstance(physical_path, str) and len(physical_path) > 512:
            errors.append(
                f"{label}.pciIdentityMatch.physicalPathOrNull: exceeds maximum length 512"
            )
        strong_providers = {
            "PCI_DSN_EUI64_V1",
            "PCI_VPD_SN_UTF8_V1",
            "VENDOR_QUALIFIED_BYTES_V1",
        }
        slot_providers = {
            "ACPI_FIRMWARE_PATH_V1": re.compile(
                r"^acpi:/[A-Z_][A-Z0-9_]{3}(?:/[A-Z_][A-Z0-9_]{3})+#adr=[0-9a-f]{16}$"
            ),
            "SMBIOS_SYSTEM_SLOT_V1": re.compile(
                r"^smbios-system-slot:/slot-id=[0-9a-f]{4}/designation=(?:[A-Za-z0-9._~-]|%[0-9A-F]{2})+/function=[0-7]$"
            ),
            "DEVICETREE_FULL_PATH_V1": re.compile(
                r"^devicetree:/(?:[A-Za-z_][A-Za-z0-9,._+\-]*(?:@[0-9a-f]+(?:,[0-9a-f]+)*)?)(?:/(?:[A-Za-z_][A-Za-z0-9,._+\-]*(?:@[0-9a-f]+(?:,[0-9a-f]+)*)?))*#function=[0-7]$"
            ),
        }
        if variant == "STRONG_SERIAL":
            if provider not in strong_providers:
                errors.append(f"{label}.pciIdentityMatch: STRONG_SERIAL provider mismatch")
            _is_digest(
                serial_hash,
                f"{label}.pciIdentityMatch.serialValueHashOrNull",
                errors,
                nonzero=True,
            )
            if physical_path is not None:
                errors.append(f"{label}.pciIdentityMatch: STRONG_SERIAL cannot carry a path")
        elif variant == "SLOT_BOUND":
            path_pattern = slot_providers.get(provider)
            if path_pattern is None:
                errors.append(f"{label}.pciIdentityMatch: SLOT_BOUND provider mismatch")
            elif not isinstance(physical_path, str) or path_pattern.fullmatch(physical_path) is None:
                errors.append(
                    f"{label}.pciIdentityMatch.physicalPathOrNull: invalid exact provider grammar"
                )
            if serial_hash is not None:
                errors.append(f"{label}.pciIdentityMatch: SLOT_BOUND cannot carry serial hash")
        else:
            errors.append(f"{label}.pciIdentityMatch.identityVariant: unknown variant")
        extractor_id = identity.get("vendorExtractorIdOrNull")
        extractor_digest = identity.get("vendorExtractorDefinitionDigestOrNull")
        if provider == "VENDOR_QUALIFIED_BYTES_V1":
            if not isinstance(extractor_id, str) or not extractor_id:
                errors.append(
                    f"{label}.pciIdentityMatch.vendorExtractorIdOrNull: required for vendor provider"
                )
            _is_digest(
                extractor_digest,
                f"{label}.pciIdentityMatch.vendorExtractorDefinitionDigestOrNull",
                errors,
                nonzero=True,
            )
        elif extractor_id is not None or extractor_digest is not None:
            errors.append(
                f"{label}.pciIdentityMatch: non-vendor provider cannot carry extractor fields"
            )
    runtime = record.get("kernelQemuFirmwareBackend")
    platform_id: str | None = None
    machine_pair: tuple[str, str] | None = None
    if isinstance(runtime, Mapping):
        for field in (
            "platformProfileId",
            "osRelease",
            "kernelRelease",
            "qemuVersion",
            "machineVersion",
        ):
            _nonempty_string(
                runtime.get(field),
                f"{label}.kernelQemuFirmwareBackend.{field}",
                errors,
            )
        runtime_enums = {
            "architecture": {"ARM64", "C86", "X86_64"},
            "machineType": {"virt", "q35", "i440fx"},
            "firmwareKind": {"UEFI", "SeaBIOS"},
            "backendFamily": {"LEGACY_VFIO_TYPE1", "VFIO_CDEV_IOMMUFD"},
            "configuredIommuType": {
                "VFIO_TYPE1V2_IOMMU",
                "VFIO_TYPE1_IOMMU",
                "IOMMUFD_IOAS",
            },
        }
        for field, allowed in runtime_enums.items():
            if runtime.get(field) not in allowed:
                errors.append(
                    f"{label}.kernelQemuFirmwareBackend.{field}: unknown closed value"
                )
        for field in (
            "kernelBuildDigest",
            "qemuBinaryDigest",
            "firmwareCodeDigest",
        ):
            _is_digest(
                runtime.get(field),
                f"{label}.kernelQemuFirmwareBackend.{field}",
                errors,
                nonzero=True,
            )
        _nullable_digest(
            runtime.get("firmwareVarsBaseDigestOrNull"),
            f"{label}.kernelQemuFirmwareBackend.firmwareVarsBaseDigestOrNull",
            errors,
            nonzero=True,
        )
        platform_id = runtime.get("platformProfileId")
        matching_platforms = [
            item
            for item in policy_mapping.get("platforms", [])
            if isinstance(item, Mapping) and item.get("id") == platform_id
        ]
        platform = matching_platforms[0] if len(matching_platforms) == 1 else None
        if len(matching_platforms) != 1:
            errors.append(
                f"{label}.kernelQemuFirmwareBackend.platformProfileId: must select "
                "exactly one complete policy platform row"
            )
        if platform is None or platform_by_id.get(platform_id) is None:
            errors.append(f"{label}.kernelQemuFirmwareBackend.platformProfileId: unknown platform")
        else:
            platform_profile_projection = {
                "profileProjectionVersion": 1,
                "policySchemaVersion": policy_mapping.get("schemaVersion"),
                "capabilityTarget": policy_mapping.get("capabilityTarget"),
                "platform": copy.deepcopy(dict(platform)),
                "backendPolicy": copy.deepcopy(
                    policy_mapping.get("backendPolicy")
                ),
                "hostConfigurationPolicy": copy.deepcopy(
                    policy_mapping.get("hostConfigurationPolicy")
                ),
            }
            expected_platform_hash = _canonical_digest(
                platform_profile_projection,
                f"{label}.platformProfileHash projection",
                errors,
            )
            if record.get("platformProfileHash") != expected_platform_hash:
                errors.append(
                    f"{label}.platformProfileHash: declared "
                    f"{record.get('platformProfileHash')}, actual {expected_platform_hash}"
                )
            exact_runtime = {
                "osRelease": platform.get("os"),
                "architecture": platform.get("architecture"),
                "kernelRelease": platform.get("kernel"),
                "qemuVersion": platform.get("qemu"),
                "backendFamily": platform.get("backendFamily"),
            }
            for field, expected in exact_runtime.items():
                if runtime.get(field) != expected:
                    errors.append(f"{label}.kernelQemuFirmwareBackend.{field}: expected {expected!r}")
            machine_pair = (runtime.get("machineType"), runtime.get("firmwareKind"))
            supported_pairs = {
                (item.get("machine"), item.get("firmware"))
                for item in platform.get("machineFirmware", [])
                if isinstance(item, Mapping)
            }
            if machine_pair not in supported_pairs:
                errors.append(
                    f"{label}.kernelQemuFirmwareBackend: machine/firmware {machine_pair} is outside exact policy"
                )
        backend = runtime.get("backendFamily")
        iommu_type = runtime.get("configuredIommuType")
        if backend == "LEGACY_VFIO_TYPE1" and iommu_type not in {"VFIO_TYPE1V2_IOMMU", "VFIO_TYPE1_IOMMU"}:
            errors.append(f"{label}.kernelQemuFirmwareBackend: Legacy backend has invalid IOMMU type")
        if backend == "VFIO_CDEV_IOMMUFD" and iommu_type != "IOMMUFD_IOAS":
            errors.append(f"{label}.kernelQemuFirmwareBackend: cdev backend requires IOMMUFD_IOAS")
    if matrix_info is None:
        errors.append(f"{label}: validated qualification case matrix is unavailable")
    else:
        matrix_digest = matrix_info.get("digest")
        if record.get("qualificationCaseMatrixSha256") != matrix_digest:
            errors.append(
                f"{label}.qualificationCaseMatrixSha256: expected exact active matrix "
                f"digest {matrix_digest!r}"
            )
        required_cases = set(matrix_info.get("global", set()))
        identity_variant = identity.get("identityVariant") if isinstance(identity, Mapping) else None
        selectors: list[tuple[str, tuple[Any, ...]]] = [
            ("platform", (platform_id,)),
            (
                "backend",
                (runtime.get("backendFamily"),) if isinstance(runtime, Mapping) else (None,),
            ),
            (
                "machine_firmware",
                (
                    runtime.get("machineType"),
                    runtime.get("firmwareKind"),
                )
                if isinstance(runtime, Mapping)
                else (None, None),
            ),
            (
                "iommu",
                (runtime.get("configuredIommuType"),)
                if isinstance(runtime, Mapping)
                else (None,),
            ),
            ("identity", (identity_variant,)),
            ("archetype", (record.get("deviceArchetype"),)),
        ]
        selected_archetype_rule: Mapping[str, Any] | None = None
        for rule_family, selector in selectors:
            family = matrix_info.get(rule_family)
            rule = family.get(selector) if isinstance(family, Mapping) else None
            if not isinstance(rule, Mapping):
                errors.append(
                    f"{label}.caseIds: missing qualification matrix rule "
                    f"{rule_family} selector {selector!r}"
                )
                continue
            required_cases.update(rule.get("caseIds", []))
            if rule_family == "archetype":
                selected_archetype_rule = rule
        record_traits = set(record.get("deviceTraits", []))
        if selected_archetype_rule is not None:
            required_traits = set(
                selected_archetype_rule.get("requiredDeviceTraits", [])
            )
            missing_traits = required_traits - record_traits
            if missing_traits:
                errors.append(
                    f"{label}.deviceTraits: archetype {record.get('deviceArchetype')!r} "
                    f"is missing mandatory traits {sorted(missing_traits)}"
                )
        trait_rules = matrix_info.get("trait")
        for trait in sorted(record_traits):
            trait_rule = (
                trait_rules.get((trait,)) if isinstance(trait_rules, Mapping) else None
            )
            if not isinstance(trait_rule, Mapping):
                errors.append(
                    f"{label}.deviceTraits: {trait!r} has no exact qualification matrix rule"
                )
            else:
                required_cases.update(trait_rule.get("caseIds", []))
        actual_cases = set(record.get("caseIds", []))
        if actual_cases != required_cases:
            errors.append(
                f"{label}.caseIds: must exactly equal qualification-matrix union "
                f"{sorted(required_cases)}; missing={sorted(required_cases - actual_cases)}, "
                f"extra={sorted(actual_cases - required_cases)}"
            )
    _verify_signed_envelope(
        record,
        digest_field="recordDigest",
        signature_field="signature",
        signer_field="qualificationSignerKeyId",
        signed_time_field="issuedAt",
        domain="QMAN-DIRECTPATH/QUALIFICATION-RECORD/V1",
        required_role="QUALIFICATION_ENGINEERING",
        trust=trust,
        label=label,
        errors=errors,
    )
    return record.get("recordDigest"), platform_id, machine_pair


def _load_e4_evidence_bundle(
    scenario: Mapping[str, Any],
    evidence_git: _GitView | None,
    root: Path,
    trust: _TrustContext | None,
    label: str,
    errors: list[str],
) -> Mapping[str, Any] | None:
    result = scenario.get("executionResult")
    if not isinstance(result, Mapping):
        errors.append(f"{label}: executionResult is missing")
        return None
    index_blob = (
        evidence_git.blob(
            result.get("executionEvidenceIndexPath"),
            f"{label}.executionEvidenceIndexPath",
            errors,
        )
        if evidence_git
        else None
    )
    _check_blob_hash(
        index_blob,
        result.get("evidenceIndexRecordSha256"),
        f"{label}.ExecutionEvidenceIndex",
        errors,
    )
    index = (
        _load_json_bytes(index_blob, f"{label}.ExecutionEvidenceIndex", errors)
        if index_blob is not None
        else None
    )
    if not isinstance(index, Mapping):
        return None
    _validate_closed_json_schema_instance(
        index,
        root,
        "contracts/directpath-execution-evidence-index.schema.json",
        f"{label}.ExecutionEvidenceIndex",
        errors,
    )
    artifacts_by_hash: dict[str, Mapping[str, Any]] = {}
    blobs_by_hash: dict[str, bytes] = {}
    for number, artifact in enumerate(index.get("artifacts", [])):
        artifact_label = f"{label}.ExecutionEvidenceIndex.artifacts[{number}]"
        if not isinstance(artifact, Mapping):
            continue
        digest = artifact.get("sha256")
        artifact_blob = (
            evidence_git.blob(artifact.get("path"), f"{artifact_label}.path", errors)
            if evidence_git
            else None
        )
        _check_blob_hash(artifact_blob, digest, artifact_label, errors)
        if isinstance(digest, str):
            artifacts_by_hash[digest] = artifact
            if artifact_blob is not None:
                blobs_by_hash[digest] = artifact_blob
    subject_hashes = [
        digest
        for digest, artifact in artifacts_by_hash.items()
        if artifact.get("artifactType") == "QUALIFICATION_SUBJECT"
    ]
    if len(subject_hashes) != 1:
        errors.append(
            f"{label}.ExecutionEvidenceIndex: expected exactly one "
            f"QUALIFICATION_SUBJECT, found {len(subject_hashes)}"
        )
        return {
            "scenario": scenario,
            "index": index,
            "artifacts": artifacts_by_hash,
            "blobs": blobs_by_hash,
            "subject": None,
            "subjectRawSha256": None,
            "subjectBlob": None,
        }
    subject_hash = subject_hashes[0]
    subject_blob = blobs_by_hash.get(subject_hash)
    subject = (
        _load_json_bytes(subject_blob, f"{label}.QualificationSubject", errors)
        if subject_blob is not None
        else None
    )
    if isinstance(subject, Mapping):
        _validate_closed_json_schema_instance(
            subject,
            root,
            "contracts/directpath-qualification-subject-manifest.schema.json",
            f"{label}.QualificationSubject",
            errors,
        )
        _verify_signed_envelope(
            subject,
            digest_field="manifestDigest",
            signature_field="signature",
            signer_field="signerKeyId",
            signed_time_field="issuedAt",
            domain="QMAN-DIRECTPATH/QUALIFICATION-SUBJECT-MANIFEST/V1",
            required_role="HOST_INVENTORY_EVIDENCE",
            trust=trust,
            label=f"{label}.QualificationSubject",
            errors=errors,
        )
    return {
        "scenario": scenario,
        "index": index,
        "artifacts": artifacts_by_hash,
        "blobs": blobs_by_hash,
        "subject": subject,
        "subjectRawSha256": subject_hash,
        "subjectBlob": subject_blob,
    }


def _json_pointer_projection(
    document: Any, pointer: Any, label: str, errors: list[str]
) -> Any:
    if not isinstance(pointer, str) or (
        pointer != "" and not pointer.startswith("/")
    ):
        errors.append(f"{label}: invalid RFC 6901 JSON pointer")
        return None
    node = document
    if pointer == "":
        return node
    for raw_token in pointer[1:].split("/"):
        if re.search(r"~(?:[^01]|$)", raw_token):
            errors.append(f"{label}: invalid JSON pointer escape")
            return None
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(node, Mapping) and token in node:
            node = node[token]
        elif isinstance(node, list) and re.fullmatch(r"0|[1-9][0-9]*", token):
            position = int(token)
            if position >= len(node):
                errors.append(f"{label}: array index is out of range")
                return None
            node = node[position]
        else:
            errors.append(f"{label}: pointer does not resolve")
            return None
    return node


def _resolve_pinned_json_descriptor(
    descriptor: Any,
    *,
    expected_schema_ref: str,
    evidence_git: _GitView | None,
    root: Path,
    label: str,
    errors: list[str],
) -> tuple[bytes | None, Mapping[str, Any] | None]:
    """Resolve a nested path/hash/length/schema descriptor without relabeling."""

    if not isinstance(descriptor, Mapping):
        errors.append(f"{label}: expected typed JSON descriptor")
        return None, None
    if descriptor.get("schemaRef") != expected_schema_ref:
        errors.append(
            f"{label}.schemaRef: expected fixed schema {expected_schema_ref!r}"
        )
    schema_path = expected_schema_ref.split("#", 1)[0]
    schema_blob = _worktree_bytes(root, schema_path, f"{label}.schemaRef", errors)
    _check_blob_hash(
        schema_blob, descriptor.get("schemaSha256"), f"{label}.schema", errors
    )
    blob = (
        evidence_git.blob(descriptor.get("path"), f"{label}.path", errors)
        if evidence_git is not None
        else None
    )
    if evidence_git is None:
        errors.append(f"{label}: pinned evidence repository E is unavailable")
    _check_blob_hash(blob, descriptor.get("sha256"), label, errors)
    if blob is not None and descriptor.get("byteLength") != len(blob):
        errors.append(
            f"{label}.byteLength: declared {descriptor.get('byteLength')!r}, "
            f"actual {len(blob)}"
        )
    if descriptor.get("mediaType") != "application/json":
        errors.append(f"{label}.mediaType: expected application/json")
    document = _load_json_bytes(blob, label, errors) if blob is not None else None
    if document is not None:
        _validate_closed_json_schema_instance(
            document, root, expected_schema_ref, label, errors
        )
    return blob, document if isinstance(document, Mapping) else None


def _verify_qualification_run_attestations(
    run: Mapping[str, Any],
    *,
    subject_issued_at: _datetime.datetime | None,
    trust: _TrustContext | None,
    evidence_git: _GitView | None,
    root: Path,
    label: str,
    errors: list[str],
) -> None:
    projection = copy.deepcopy(dict(run))
    projection["runDigest"] = None
    projection["attestations"] = []
    expected_run_digest = _canonical_digest(
        projection, f"{label}.runDigest projection", errors
    )
    if run.get("runDigest") != expected_run_digest:
        errors.append(f"{label}.runDigest: canonical projection mismatch")
    attestations = run.get("attestations")
    if not isinstance(attestations, list):
        errors.append(f"{label}.attestations: expected array")
        return
    roles = [
        item.get("signerRole")
        for item in attestations
        if isinstance(item, Mapping) and isinstance(item.get("signerRole"), str)
    ]
    if roles != ["HOST_INVENTORY_EVIDENCE", "TEST_EVIDENCE"]:
        errors.append(
            f"{label}.attestations: expected exact independent role order "
            "[HOST_INVENTORY_EVIDENCE, TEST_EVIDENCE]"
        )
    run_finished = _parse_time(run.get("finishedAt"), f"{label}.finishedAt", errors)
    principals: set[str] = set()
    key_ids: set[str] = set()
    public_keys: set[str] = set()
    signatures: set[str] = set()
    for number, attestation in enumerate(attestations):
        attestation_label = f"{label}.attestations[{number}]"
        if not isinstance(attestation, Mapping):
            errors.append(f"{attestation_label}: expected object")
            continue
        role = attestation.get("signerRole")
        signed_subject = {
            "signerRole": role,
            "principalId": attestation.get("principalId"),
            "signerKeyId": attestation.get("signerKeyId"),
            "signedAt": attestation.get("signedAt"),
            "runDigest": run.get("runDigest"),
        }
        try:
            preimage = (
                b"QMAN-DIRECTPATH/QUALIFICATION-RUN-MANIFEST-ATTESTATION/V1\x00"
                + canonical_json_bytes(signed_subject)
            )
        except (CanonicalizationError, TypeError, ValueError) as exc:
            errors.append(f"{attestation_label}: cannot canonicalize subject: {exc}")
            preimage = None
        ring, key = _trust_key_at_history_version(
            trust,
            run.get("keyRingVersion"),
            attestation.get("signerKeyId"),
            evidence_git,
            root,
            attestation_label,
            errors,
        )
        signed_at = _parse_time(
            attestation.get("signedAt"), f"{attestation_label}.signedAt", errors
        )
        if run_finished is not None and signed_at is not None and signed_at < run_finished:
            errors.append(f"{attestation_label}.signedAt: predates run completion")
        if (
            subject_issued_at is not None
            and signed_at is not None
            and signed_at > subject_issued_at
        ):
            errors.append(f"{attestation_label}.signedAt: postdates Subject issuance")
        if isinstance(key, Mapping):
            key_roles = key.get("roles")
            if not isinstance(role, str) or not isinstance(key_roles, list) or role not in key_roles:
                errors.append(f"{attestation_label}: signer key lacks declared role")
            if key.get("principalId") != attestation.get("principalId"):
                errors.append(f"{attestation_label}.principalId: key principal mismatch")
            key_before = _parse_time(
                key.get("notBefore"), f"{attestation_label}.key.notBefore", errors
            )
            key_after = _parse_time(
                key.get("notAfter"), f"{attestation_label}.key.notAfter", errors
            )
            revoked_at = (
                _parse_time(
                    key.get("revokedAtOrNull"),
                    f"{attestation_label}.key.revokedAt",
                    errors,
                )
                if key.get("revokedAtOrNull") is not None
                else None
            )
            if signed_at is not None:
                if (
                    key_before is not None
                    and key_after is not None
                    and not (key_before <= signed_at < key_after)
                ):
                    errors.append(f"{attestation_label}: key validity mismatch")
                if revoked_at is not None and signed_at >= revoked_at:
                    errors.append(f"{attestation_label}: key was revoked")
            public_key = key.get("publicKeyBase64Url")
            if preimage is not None:
                _verify_ed25519(
                    public_key,
                    attestation.get("signature"),
                    preimage,
                    attestation_label,
                    errors,
                )
            if isinstance(public_key, str):
                if public_key in public_keys:
                    errors.append(f"{attestation_label}: reused public-key material")
                public_keys.add(public_key)
        if isinstance(ring, Mapping) and signed_at is not None:
            ring_before = _parse_time(
                ring.get("notBefore"), f"{attestation_label}.ring.notBefore", errors
            )
            ring_after = _parse_time(
                ring.get("expiresAt"), f"{attestation_label}.ring.expiresAt", errors
            )
            if (
                ring_before is not None
                and ring_after is not None
                and not (ring_before <= signed_at < ring_after)
            ):
                errors.append(f"{attestation_label}: key-ring validity mismatch")
        for field, seen in (
            ("principalId", principals),
            ("signerKeyId", key_ids),
            ("signature", signatures),
        ):
            value = attestation.get(field)
            if not isinstance(value, str):
                continue
            if value in seen:
                errors.append(f"{attestation_label}.{field}: duplicate identity")
            seen.add(value)


def _require_canonical_object_order(
    values: Any,
    fields: Sequence[str],
    label: str,
    errors: list[str],
) -> list[Mapping[str, Any]]:
    """Require a list of objects to be unique and ordered by a closed key."""

    if not isinstance(values, list):
        errors.append(f"{label}: expected array")
        return []
    records = [value for value in values if isinstance(value, Mapping)]
    if len(records) != len(values):
        errors.append(f"{label}: every element must be an object")
    order: list[bytes] = []
    for number, value in enumerate(records):
        try:
            key: Any = value.get(fields[0]) if len(fields) == 1 else [
                value.get(field) for field in fields
            ]
            order.append(canonical_json_bytes(key))
        except (CanonicalizationError, TypeError, ValueError) as exc:
            errors.append(f"{label}[{number}]: invalid order key: {exc}")
    if order != sorted(order) or len(order) != len(set(order)):
        errors.append(f"{label}: non-canonical or duplicate order key")
    return records


def _validate_workload_entrypoint_artifact(
    descriptor: Any,
    *,
    evidence_git: _GitView | None,
    root: Path,
    label: str,
    errors: list[str],
) -> bytes | None:
    if not isinstance(descriptor, Mapping):
        errors.append(f"{label}: expected artifact descriptor")
        return None
    blob = (
        evidence_git.blob(descriptor.get("path"), f"{label}.path", errors)
        if evidence_git is not None
        else None
    )
    if evidence_git is None:
        errors.append(f"{label}: pinned evidence repository E is unavailable")
    _check_blob_hash(blob, descriptor.get("sha256"), label, errors)
    if blob is not None and descriptor.get("byteLength") != len(blob):
        errors.append(f"{label}.byteLength: raw artifact mismatch")
    schema_ref = descriptor.get("schemaRefOrNull")
    schema_digest = descriptor.get("schemaSha256OrNull")
    if (schema_ref is None) != (schema_digest is None):
        errors.append(f"{label}: schemaRef/schemaSha256 tuple is partial")
    if isinstance(schema_ref, str) and isinstance(schema_digest, str):
        schema_path = schema_ref.split("#", 1)[0]
        schema_blob = _worktree_bytes(
            root, schema_path, f"{label}.schemaRef", errors
        )
        _check_blob_hash(schema_blob, schema_digest, f"{label}.schema", errors)
        document = _load_json_bytes(blob, label, errors) if blob is not None else None
        if document is not None:
            _validate_closed_json_schema_instance(
                document, root, schema_ref, label, errors
            )
    return blob


def _validate_workload_evaluator_manifest(
    descriptor: Any,
    *,
    request: Mapping[str, Any],
    code_git: _GitView | None,
    evidence_git: _GitView | None,
    root: Path,
    mapping: Mapping[str, Any] | None,
    trust: _TrustContext | None,
    label: str,
    errors: list[str],
) -> Mapping[str, Any] | None:
    schema_ref = "contracts/directpath-workload-evaluator-manifest.schema.json"
    _blob, manifest = _resolve_pinned_json_descriptor(
        descriptor,
        expected_schema_ref=schema_ref,
        evidence_git=evidence_git,
        root=root,
        label=label,
        errors=errors,
    )
    if not isinstance(descriptor, Mapping) or not isinstance(manifest, Mapping):
        return None
    _verify_history_signed_envelope(
        manifest,
        digest_field="manifestDigest",
        signature_field="signature",
        signer_field="signerKeyId",
        signed_time_field="createdAt",
        domain="QMAN-DIRECTPATH/WORKLOAD-EVALUATOR-MANIFEST/V1",
        required_role="TEST_EVIDENCE",
        trust=trust,
        evidence_git=evidence_git,
        root=root,
        label=label,
        errors=errors,
    )
    for field in ("manifestId", "manifestDigest"):
        if descriptor.get(field) != manifest.get(field):
            errors.append(f"{label}.{field}: parsed evaluator manifest mismatch")
    exact_manifest = {
        "mappingCoreId": request.get("mappingCoreId"),
        "portableContractSha256": request.get("portableContractSha256"),
    }
    for field, expected in exact_manifest.items():
        if manifest.get(field) != expected:
            errors.append(f"{label}.{field}: QualificationRunRequest mismatch")
    manifest_commit = _normal_commit(
        manifest.get("targetRepositoryCommit"),
        f"{label}.targetRepositoryCommit",
        errors,
    )
    request_commit = _normal_commit(
        request.get("targetRepositoryCommit"),
        f"{label}.request.targetRepositoryCommit",
        errors,
    )
    if manifest_commit != request_commit:
        errors.append(f"{label}.targetRepositoryCommit: request mismatch")

    evaluator = manifest.get("evaluator")
    if isinstance(evaluator, Mapping):
        evaluator_blob = (
            code_git.blob(evaluator.get("path"), f"{label}.evaluator.path", errors)
            if code_git is not None
            else None
        )
        if code_git is None:
            errors.append(f"{label}.evaluator: target repository C is unavailable")
        _check_blob_hash(
            evaluator_blob,
            evaluator.get("blobSha256"),
            f"{label}.evaluator",
            errors,
        )
        binding_matches: list[Mapping[str, Any]] = []
        if isinstance(mapping, Mapping):
            binding_matches = [
                binding
                for entry in mapping.get("mappings", [])
                if isinstance(entry, Mapping)
                for binding in entry.get("targetBindings", [])
                if isinstance(binding, Mapping)
                and binding.get("path") == evaluator.get("path")
                and binding.get("symbol") == evaluator.get("symbol")
                and binding.get("hashScope") == "GIT_BLOB_BYTES"
                and binding.get("interfaceHash") == evaluator.get("blobSha256")
                and binding.get("symbolSemanticHash")
                == evaluator.get("symbolSemanticHash")
                and binding.get("symbolKind") in {"FUNCTION", "TEST"}
            ]
        if len(binding_matches) != 1:
            errors.append(
                f"{label}.evaluator: path/blob interface resolves "
                f"{len(binding_matches)} signed target bindings"
            )
    else:
        errors.append(f"{label}.evaluator: expected object")

    source_tree = manifest.get("sourceTree")
    tracked_paths: set[str] = set()
    if isinstance(source_tree, Mapping):
        source_blob = (
            evidence_git.blob(source_tree.get("path"), f"{label}.sourceTree.path", errors)
            if evidence_git is not None
            else None
        )
        _check_blob_hash(
            source_blob, source_tree.get("sha256"), f"{label}.sourceTree", errors
        )
        if source_blob is not None and source_tree.get("byteLength") != len(source_blob):
            errors.append(f"{label}.sourceTree.byteLength: raw manifest mismatch")
        source_manifest = _validate_source_tree_manifest(
            {
                "sourceTreeManifestPath": source_tree.get("path"),
                "sourceTreeManifestSha256": source_tree.get("sha256"),
                "sourceTreeManifestSchemaSha256": source_tree.get("schemaSha256"),
                "sourceTreeSha256": source_tree.get("sourceTreeSha256"),
            },
            code_git,
            evidence_git,
            root,
            f"{label}.sourceTree",
            errors,
            _tracked_paths=tracked_paths,
        )
        if (
            isinstance(source_manifest, Mapping)
            and isinstance(evaluator, Mapping)
            and evaluator.get("path") not in tracked_paths
        ):
            errors.append(f"{label}.sourceTree: evaluator path is absent")
    else:
        errors.append(f"{label}.sourceTree: expected descriptor")

    build_bundle = _validate_build_attestation(
        manifest.get("buildAttestation"),
        expected_consumer_kind="WORKLOAD_EVALUATOR",
        expected_consumer_build_id=manifest.get("manifestId"),
        expected_target_commit=manifest.get("targetRepositoryCommit"),
        expected_mapping_core_id=manifest.get("mappingCoreId"),
        expected_portable_contract_sha256=manifest.get("portableContractSha256"),
        expected_source_tree=(
            dict(source_tree) if isinstance(source_tree, Mapping) else None
        ),
        code_git=code_git,
        evidence_git=evidence_git,
        root=root,
        trust=trust,
        label=f"{label}.buildAttestation",
        errors=errors,
    )
    build_attestation = (
        build_bundle.get("attestation")
        if isinstance(build_bundle, Mapping)
        and isinstance(build_bundle.get("attestation"), Mapping)
        else None
    )
    build_artifacts = (
        build_bundle.get("artifacts")
        if isinstance(build_bundle, Mapping)
        and isinstance(build_bundle.get("artifacts"), Mapping)
        else None
    )
    if isinstance(build_attestation, Mapping):
        attested_at = _parse_time(
            build_attestation.get("attestedAt"),
            f"{label}.buildAttestation.attestedAt",
            errors,
        )
        created_at = _parse_time(manifest.get("createdAt"), f"{label}.createdAt", errors)
        if (
            attested_at is not None
            and created_at is not None
            and attested_at >= created_at
        ):
            errors.append(f"{label}.createdAt: must follow BuildAttestation")

    environment = manifest.get("executionEnvironment")
    environment_artifacts: list[Mapping[str, Any]] = []
    if isinstance(environment, Mapping):
        for role in (
            "runtimeBinary",
            "dependencyLock",
            "environmentManifest",
            "buildLog",
        ):
            artifact = environment.get(role)
            artifact_label = f"{label}.executionEnvironment.{role}"
            if not isinstance(artifact, Mapping):
                errors.append(f"{artifact_label}: expected artifact descriptor")
                continue
            environment_artifacts.append(artifact)
            artifact_blob = (
                evidence_git.blob(artifact.get("path"), f"{artifact_label}.path", errors)
                if evidence_git is not None
                else None
            )
            _check_blob_hash(
                artifact_blob, artifact.get("sha256"), artifact_label, errors
            )
            if artifact_blob is not None and artifact.get("byteLength") != len(
                artifact_blob
            ):
                errors.append(f"{artifact_label}.byteLength: mismatch")
    else:
        errors.append(f"{label}.executionEnvironment: expected object")
    paths = [
        item.get("path")
        for item in environment_artifacts
        if isinstance(item.get("path"), str)
    ]
    hashes = [
        item.get("sha256")
        for item in environment_artifacts
        if isinstance(item.get("sha256"), str)
    ]
    if len(set(paths)) != 4 or len(set(hashes)) != 4:
        errors.append(
            f"{label}.executionEnvironment: four paths/hashes must be distinct"
        )
    reserved_descriptors = [
        item
        for item in (descriptor, source_tree, manifest.get("buildAttestation"))
        if isinstance(item, Mapping)
    ]
    reserved_paths = {
        item.get("path")
        for item in reserved_descriptors
        if isinstance(item.get("path"), str)
    }
    reserved_hashes = {
        item.get("sha256")
        for item in reserved_descriptors
        if isinstance(item.get("sha256"), str)
    }
    if len(reserved_paths) != len(reserved_descriptors) or len(
        reserved_hashes
    ) != len(reserved_descriptors):
        errors.append(
            f"{label}: manifest/source-tree/build roles require distinct paths/hashes"
        )
    if set(paths) & reserved_paths or set(hashes) & reserved_hashes:
        errors.append(
            f"{label}.executionEnvironment: runtime artifact reuses a "
            "manifest/source-tree/build role"
        )

    if (
        isinstance(build_attestation, Mapping)
        and isinstance(build_artifacts, Mapping)
        and isinstance(environment, Mapping)
    ):
        output = build_attestation.get("output")
        mode = build_attestation.get("mode")
        runtime_binary = environment.get("runtimeBinary")
        if mode == "INTERPRETED_NO_BUILD":
            if environment.get("mode") != "INTERPRETED":
                errors.append(f"{label}.executionEnvironment.mode: expected INTERPRETED")
            if (
                not isinstance(output, Mapping)
                or output.get("kind") != "INTERPRETED_RUNTIME"
                or output.get("role") != "WORKLOAD_EVALUATOR_SOURCE"
            ):
                errors.append(f"{label}.buildAttestation.output: interpreted role mismatch")
            elif isinstance(output.get("entrypointSource"), Mapping):
                entrypoint = output["entrypointSource"]
                if not isinstance(evaluator, Mapping) or (
                    entrypoint.get("path") != evaluator.get("path")
                    or entrypoint.get("contentSha256") != evaluator.get("blobSha256")
                ):
                    errors.append(
                        f"{label}.buildAttestation.output: evaluator entrypoint mismatch"
                    )
            toolchain = build_attestation.get("toolchain")
            interpreter_id = output.get("interpreterComponentId") if isinstance(
                output, Mapping
            ) else None
            interpreter_components = [
                item
                for item in (
                    toolchain.get("components", [])
                    if isinstance(toolchain, Mapping)
                    else []
                )
                if isinstance(item, Mapping)
                and item.get("componentId") == interpreter_id
                and item.get("role") == "INTERPRETER"
            ]
            interpreter_artifact = (
                interpreter_components[0].get("artifact")
                if len(interpreter_components) == 1
                else None
            )
            if runtime_binary != interpreter_artifact:
                errors.append(
                    f"{label}.executionEnvironment.runtimeBinary: interpreter mismatch"
                )
        else:
            if environment.get("mode") == "INTERPRETED":
                errors.append(f"{label}.executionEnvironment.mode: produced mismatch")
            if (
                not isinstance(output, Mapping)
                or output.get("kind") != "PRODUCED_ARTIFACT"
                or output.get("role") != "WORKLOAD_EVALUATOR_BINARY"
                or output.get("executable") is not True
            ):
                errors.append(f"{label}.buildAttestation.output: produced role mismatch")
            else:
                if output.get("consumerRuntimeMode") != environment.get("mode"):
                    errors.append(f"{label}.executionEnvironment.mode: output mismatch")
                if runtime_binary != output.get("artifact"):
                    errors.append(
                        f"{label}.executionEnvironment.runtimeBinary: output mismatch"
                    )
        exact_environment = {
            "dependencyLock": build_artifacts.get("dependencies.lockArtifact"),
            "environmentManifest": build_artifacts.get("environment.manifest"),
            "buildLog": build_artifacts.get("buildLog"),
        }
        for role, expected in exact_environment.items():
            if environment.get(role) != expected:
                errors.append(f"{label}.executionEnvironment.{role}: build mismatch")

    schema_contracts: list[tuple[str, Mapping[str, Any]]] = []
    inputs = manifest.get("inputContracts")
    if isinstance(inputs, Mapping):
        expected_refs = {
            "workloadDefinition": (
                "contracts/directpath-qualification-workload-definition.schema.json"
            ),
            "runRequest": "contracts/directpath-qualification-run-request.schema.json",
            "artifactObservationSet": (
                "contracts/directpath-workload-evaluation-report.schema.json"
                "#/$defs/artifactObservationSet"
            ),
            "evaluationContext": (
                "contracts/directpath-workload-evaluation-report.schema.json"
                "#/$defs/evaluationContext"
            ),
        }
        for role, expected_ref in expected_refs.items():
            contract = inputs.get(role)
            if not isinstance(contract, Mapping):
                errors.append(f"{label}.inputContracts.{role}: expected schema contract")
                continue
            schema_contracts.append((role, contract))
            if contract.get("schemaRef") != expected_ref:
                errors.append(f"{label}.inputContracts.{role}.schemaRef: mismatch")
    output_contract = manifest.get("outputContract")
    if isinstance(output_contract, Mapping):
        schema_contracts.append(("outputContract", output_contract))
        if output_contract.get("schemaRef") != (
            "contracts/directpath-workload-evaluation-report.schema.json"
        ):
            errors.append(f"{label}.outputContract.schemaRef: mismatch")
    else:
        errors.append(f"{label}.outputContract: expected schema contract")
    for role, contract in schema_contracts:
        ref = contract.get("schemaRef")
        schema_path = ref.split("#", 1)[0] if isinstance(ref, str) else None
        schema_blob = _worktree_bytes(
            root, schema_path, f"{label}.{role}.schemaRef", errors
        )
        _check_blob_hash(
            schema_blob, contract.get("schemaSha256"), f"{label}.{role}.schema", errors
        )
    if isinstance(evaluator, Mapping):
        interface_projection = {
            "protocol": evaluator.get("protocol"),
            "argvOrder": [
                "definition",
                "request",
                "observations",
                "context",
                "evidenceRoot",
                "output",
            ],
            "environment": {"LC_ALL": "C.UTF-8", "TZ": "UTC"},
            "network": "DENY_ALL",
            "inputContracts": copy.deepcopy(manifest.get("inputContracts")),
            "observationArtifactAccess": manifest.get(
                "observationArtifactAccess"
            ),
            "outputContract": copy.deepcopy(manifest.get("outputContract")),
            "numericSemantics": copy.deepcopy(manifest.get("numericSemantics")),
        }
        expected_interface_digest = _canonical_digest(
            interface_projection,
            f"{label}.evaluator.interfaceContractDigest projection",
            errors,
        )
        if evaluator.get("interfaceContractDigest") != expected_interface_digest:
            errors.append(
                f"{label}.evaluator.interfaceContractDigest: projection mismatch"
            )
    return manifest


def _validate_qualification_workload_definition(
    descriptor: Any,
    *,
    request: Mapping[str, Any],
    subject: Mapping[str, Any],
    record: Mapping[str, Any],
    code_git: _GitView | None,
    evidence_git: _GitView | None,
    root: Path,
    mapping: Mapping[str, Any] | None,
    trust: _TrustContext | None,
    label: str,
    errors: list[str],
) -> Mapping[str, Any] | None:
    schema_ref = "contracts/directpath-qualification-workload-definition.schema.json"
    _blob, definition = _resolve_pinned_json_descriptor(
        descriptor,
        expected_schema_ref=schema_ref,
        evidence_git=evidence_git,
        root=root,
        label=label,
        errors=errors,
    )
    if not isinstance(descriptor, Mapping) or not isinstance(definition, Mapping):
        return None
    _verify_history_signed_envelope(
        definition,
        digest_field="definitionDigest",
        signature_field="signature",
        signer_field="signerKeyId",
        signed_time_field="issuedAt",
        domain="QMAN-DIRECTPATH/QUALIFICATION-WORKLOAD-DEFINITION/V1",
        required_role="TEST_EVIDENCE",
        trust=trust,
        evidence_git=evidence_git,
        root=root,
        label=label,
        errors=errors,
    )
    if descriptor.get("definitionDigest") != definition.get("definitionDigest"):
        errors.append(f"{label}.definitionDigest: parsed definition mismatch")
    definition_exact = {
        "workloadId": request.get("workloadId"),
        "definitionDigest": request.get("workloadDefinitionDigest"),
        "minimumDurationSeconds": request.get("minimumDurationSeconds"),
    }
    for field, expected in definition_exact.items():
        if definition.get(field) != expected:
            errors.append(f"{label}.{field}: QualificationRunRequest mismatch")
    definition_issued = _parse_time(
        definition.get("issuedAt"), f"{label}.issuedAt", errors
    )
    request_issued = _parse_time(
        request.get("issuedAt"), f"{label}.request.issuedAt", errors
    )
    if (
        definition_issued is not None
        and request_issued is not None
        and definition_issued >= request_issued
    ):
        errors.append(f"{label}: definition must be signed before the request")

    evaluator_manifest = _validate_workload_evaluator_manifest(
        definition.get("evaluatorManifest"),
        request=request,
        code_git=code_git,
        evidence_git=evidence_git,
        root=root,
        mapping=mapping,
        trust=trust,
        label=f"{label}.evaluatorManifest",
        errors=errors,
    )
    if isinstance(evaluator_manifest, Mapping):
        evaluator_created = _parse_time(
            evaluator_manifest.get("createdAt"),
            f"{label}.evaluatorManifest.createdAt",
            errors,
        )
        if (
            evaluator_created is not None
            and definition_issued is not None
            and evaluator_created >= definition_issued
        ):
            errors.append(f"{label}: evaluator manifest must predate definition")
    evaluator_id = (
        evaluator_manifest.get("manifestId")
        if isinstance(evaluator_manifest, Mapping)
        else None
    )
    evaluator_digest = (
        evaluator_manifest.get("manifestDigest")
        if isinstance(evaluator_manifest, Mapping)
        else None
    )

    guest = record.get("guestDriverAndWorkload")
    runtime = record.get("kernelQemuFirmwareBackend")
    providers = record.get("iommuInterruptResetProviders")
    if isinstance(guest, Mapping) and isinstance(runtime, Mapping):
        measured_qualification_tuple = {
            "guest": {
                "guestAbiClass": guest.get("guestAbiClass"),
                "guestArchitecture": guest.get("guestArchitecture"),
                "guestOs": guest.get("guestOs"),
                "guestKernel": guest.get("guestKernel"),
                "driverName": guest.get("guestDriverName"),
                "driverVersion": guest.get("guestDriverVersion"),
                "driverDigest": guest.get("guestDriverDigest"),
            },
            "runtime": {
                "platformProfileId": runtime.get("platformProfileId"),
                "backendFamily": runtime.get("backendFamily"),
                "configuredIommuType": runtime.get("configuredIommuType"),
                "machineType": runtime.get("machineType"),
                "firmwareKind": runtime.get("firmwareKind"),
            },
        }
        qualification_tuples = _require_canonical_object_order(
            definition.get("supportedQualificationTuples"),
            ("guest", "runtime"),
            f"{label}.supportedQualificationTuples",
            errors,
        )
        if sum(
            item == measured_qualification_tuple for item in qualification_tuples
        ) != 1:
            errors.append(
                f"{label}.supportedQualificationTuples: exact measured twelve-field "
                "guest/runtime tuple is absent or ambiguous"
            )
    else:
        errors.append(
            f"{label}.supportedQualificationTuples: measured guest/runtime is unavailable"
        )
    guest_prerequisites = definition.get("guestPrerequisites")
    if isinstance(guest, Mapping) and isinstance(guest_prerequisites, Mapping):
        required_guest_capabilities = {
            item
            for item in (
                guest_prerequisites.get("requiredGuestCapabilities", [])
                if isinstance(
                    guest_prerequisites.get("requiredGuestCapabilities"), list
                )
                else []
            )
            if isinstance(item, str)
        }
        measured_guest_capabilities = {
            item
            for item in (
                guest.get("guestCapabilities", [])
                if isinstance(guest.get("guestCapabilities"), list)
                else []
            )
            if isinstance(item, str)
        }
        if not required_guest_capabilities.issubset(measured_guest_capabilities):
            errors.append(
                f"{label}.guestPrerequisites.requiredGuestCapabilities: "
                "measured guest mismatch"
            )
        _require_canonical_set_order(
            guest_prerequisites.get("requiredGuestCapabilities"),
            f"{label}.guestPrerequisites.requiredGuestCapabilities",
            errors,
        )
    else:
        errors.append(f"{label}.guestPrerequisites: measured guest is unavailable")

    runtime_prerequisites = definition.get("runtimePrerequisites")
    if isinstance(runtime, Mapping) and isinstance(runtime_prerequisites, Mapping):
        device_archetypes = runtime_prerequisites.get("deviceArchetypes")
        if not isinstance(device_archetypes, list) or record.get(
            "deviceArchetype"
        ) not in device_archetypes:
            errors.append(
                f"{label}.runtimePrerequisites.deviceArchetypes: subject mismatch"
            )
        _require_canonical_set_order(
            device_archetypes,
            f"{label}.runtimePrerequisites.deviceArchetypes",
            errors,
        )
        required_traits = {
            item
            for item in (
                runtime_prerequisites.get("requiredDeviceTraits", [])
                if isinstance(
                    runtime_prerequisites.get("requiredDeviceTraits"), list
                )
                else []
            )
            if isinstance(item, str)
        }
        actual_traits = {
            item
            for item in (
                record.get("deviceTraits", [])
                if isinstance(record.get("deviceTraits"), list)
                else []
            )
            if isinstance(item, str)
        }
        if not required_traits.issubset(actual_traits):
            errors.append(
                f"{label}.runtimePrerequisites.requiredDeviceTraits: subject mismatch"
            )
        provider_ids = {
            value
            for field, value in (providers.items() if isinstance(providers, Mapping) else [])
            if (field.endswith("ProviderId") or field == "dmaIrqObserverId")
            and isinstance(value, str)
        }
        required_providers = {
            item
            for item in (
                runtime_prerequisites.get("requiredProviderIds", [])
                if isinstance(runtime_prerequisites.get("requiredProviderIds"), list)
                else []
            )
            if isinstance(item, str)
        }
        if not required_providers.issubset(provider_ids):
            errors.append(
                f"{label}.runtimePrerequisites.requiredProviderIds: subject mismatch"
            )
        required_runtime_capabilities = {
            item
            for item in (
                runtime_prerequisites.get("requiredRuntimeCapabilities", [])
                if isinstance(
                    runtime_prerequisites.get("requiredRuntimeCapabilities"), list
                )
                else []
            )
            if isinstance(item, str)
        }
        measured_runtime_capabilities = {
            item
            for item in (
                runtime.get("runtimeCapabilities", [])
                if isinstance(runtime.get("runtimeCapabilities"), list)
                else []
            )
            if isinstance(item, str)
        }
        if not required_runtime_capabilities.issubset(
            measured_runtime_capabilities
        ):
            errors.append(
                f"{label}.runtimePrerequisites.requiredRuntimeCapabilities: "
                "measured runtime mismatch"
            )
        minimum_vcpus = runtime_prerequisites.get("minimumVcpus")
        minimum_memory = runtime_prerequisites.get("minimumMemoryMiB")
        if not isinstance(guest.get("guestVcpuCount"), int) or (
            isinstance(minimum_vcpus, int)
            and guest.get("guestVcpuCount") < minimum_vcpus
        ):
            errors.append(
                f"{label}.runtimePrerequisites.minimumVcpus: measured guest mismatch"
            )
        if not isinstance(guest.get("guestMemoryMiB"), int) or (
            isinstance(minimum_memory, int)
            and guest.get("guestMemoryMiB") < minimum_memory
        ):
            errors.append(
                f"{label}.runtimePrerequisites.minimumMemoryMiB: "
                "measured guest mismatch"
            )
        for field in (
            "requiredDeviceTraits",
            "requiredProviderIds",
            "requiredRuntimeCapabilities",
        ):
            _require_canonical_set_order(
                runtime_prerequisites.get(field),
                f"{label}.runtimePrerequisites.{field}",
                errors,
            )
    else:
        errors.append(f"{label}.runtimePrerequisites: measured runtime is unavailable")

    entrypoint = definition.get("entrypoint")
    entrypoint_artifacts: list[Mapping[str, Any]] = []
    if isinstance(entrypoint, Mapping):
        for name in ("binary", "configuration"):
            artifact = entrypoint.get(name)
            if isinstance(artifact, Mapping):
                entrypoint_artifacts.append(artifact)
            _validate_workload_entrypoint_artifact(
                artifact,
                evidence_git=evidence_git,
                root=root,
                label=f"{label}.entrypoint.{name}",
                errors=errors,
            )
    else:
        errors.append(f"{label}.entrypoint: expected object")
    for field in ("artifactId", "path", "sha256"):
        values = [artifact.get(field) for artifact in entrypoint_artifacts]
        if (
            len(values) != 2
            or not all(isinstance(value, str) for value in values)
            or len(set(values)) != 2
        ):
            errors.append(f"{label}.entrypoint.{field}: must be independently unique")

    invocation = definition.get("canonicalInvocation")
    if isinstance(invocation, Mapping) and len(entrypoint_artifacts) == 2:
        if invocation.get("executableArtifactId") != entrypoint_artifacts[0].get(
            "artifactId"
        ):
            errors.append(f"{label}.canonicalInvocation.executableArtifactId: mismatch")
        if invocation.get("configurationArtifactId") != entrypoint_artifacts[1].get(
            "artifactId"
        ):
            errors.append(
                f"{label}.canonicalInvocation.configurationArtifactId: mismatch"
            )
        timeout = invocation.get("timeoutSeconds")
        minimum = definition.get("minimumDurationSeconds")
        grace = invocation.get("terminationGraceSeconds")
        if all(isinstance(value, int) for value in (timeout, minimum, grace)) and (
            timeout < minimum + grace
        ):
            errors.append(f"{label}.canonicalInvocation.timeoutSeconds: too short")
        environment = _require_canonical_object_order(
            invocation.get("environment"),
            ("name",),
            f"{label}.canonicalInvocation.environment",
            errors,
        )
        names = [item.get("name") for item in environment]
        if len(names) != len(set(names)):
            errors.append(f"{label}.canonicalInvocation.environment: duplicate name")
        exit_codes = invocation.get("expectedExitCodes")
        if isinstance(exit_codes, list) and (
            exit_codes != sorted(exit_codes) or len(exit_codes) != len(set(exit_codes))
        ):
            errors.append(
                f"{label}.canonicalInvocation.expectedExitCodes: non-canonical set"
            )
    else:
        errors.append(f"{label}.canonicalInvocation: expected object")

    required_roles = definition.get("requiredArtifactRoles")
    _require_canonical_set_order(
        required_roles, f"{label}.requiredArtifactRoles", errors
    )
    required_role_set = {
        role
        for role in (required_roles if isinstance(required_roles, list) else [])
        if isinstance(role, str)
    }
    assertions = _require_canonical_object_order(
        definition.get("mandatoryAssertions"),
        ("assertionId",),
        f"{label}.mandatoryAssertions",
        errors,
    )
    seen_assertion_ids: set[Any] = set()
    seen_assertion_digests: set[Any] = set()
    seen_oracle_ids: set[Any] = set()
    for number, assertion in enumerate(assertions):
        assertion_label = f"{label}.mandatoryAssertions[{number}]"
        projection = {
            field: copy.deepcopy(assertion.get(field))
            for field in ("assertionId", "statement", "oracle", "requiredEvidenceRoles")
        }
        expected_digest = _canonical_digest(
            projection, f"{assertion_label}.assertionDigest projection", errors
        )
        if assertion.get("assertionDigest") != expected_digest:
            errors.append(f"{assertion_label}.assertionDigest: projection mismatch")
        oracle = assertion.get("oracle")
        oracle_id = oracle.get("oracleId") if isinstance(oracle, Mapping) else None
        if isinstance(oracle, Mapping):
            expression = oracle.get("expression")
            expression_digest = (
                sha256(expression.encode("utf-8"))
                if isinstance(expression, str)
                else None
            )
            if oracle.get("expressionSha256") != expression_digest:
                errors.append(
                    f"{assertion_label}.oracle.expressionSha256: raw UTF-8 mismatch"
                )
            if oracle.get("evaluatorId") != evaluator_id or oracle.get(
                "evaluatorDefinitionDigest"
            ) != evaluator_digest:
                errors.append(
                    f"{assertion_label}.oracle: evaluator manifest mismatch"
                )
        for field, value, seen in (
            ("assertionId", assertion.get("assertionId"), seen_assertion_ids),
            ("assertionDigest", assertion.get("assertionDigest"), seen_assertion_digests),
            ("oracle.oracleId", oracle_id, seen_oracle_ids),
        ):
            if not isinstance(value, str):
                errors.append(f"{assertion_label}.{field}: expected identifier")
                continue
            if value in seen:
                errors.append(f"{assertion_label}.{field}: duplicate identity")
            seen.add(value)
        assertion_roles = assertion.get("requiredEvidenceRoles")
        _require_canonical_set_order(
            assertion_roles, f"{assertion_label}.requiredEvidenceRoles", errors
        )
        assertion_role_set = {
            role
            for role in (assertion_roles if isinstance(assertion_roles, list) else [])
            if isinstance(role, str)
        }
        if not assertion_role_set.issubset(required_role_set):
            errors.append(f"{assertion_label}.requiredEvidenceRoles: outside vocabulary")

    metrics = _require_canonical_object_order(
        definition.get("metricDefinitions"),
        ("metricId",),
        f"{label}.metricDefinitions",
        errors,
    )
    seen_metric_ids: set[Any] = set()
    seen_metric_digests: set[Any] = set()
    for number, metric in enumerate(metrics):
        metric_label = f"{label}.metricDefinitions[{number}]"
        projection = {
            field: copy.deepcopy(metric.get(field))
            for field in (
                "metricId",
                "evaluatorId",
                "evaluatorDefinitionDigest",
                "exactValueProjection",
                "aggregation",
                "outputScale",
                "unit",
                "sourceRoleAllowlist",
                "valueContract",
            )
        }
        expected_digest = _canonical_digest(
            projection, f"{metric_label}.metricDefinitionDigest projection", errors
        )
        if metric.get("metricDefinitionDigest") != expected_digest:
            errors.append(
                f"{metric_label}.metricDefinitionDigest: projection mismatch"
            )
        if metric.get("evaluatorId") != evaluator_id or metric.get(
            "evaluatorDefinitionDigest"
        ) != evaluator_digest:
            errors.append(f"{metric_label}: evaluator manifest mismatch")
        for field, value, seen in (
            ("metricId", metric.get("metricId"), seen_metric_ids),
            (
                "metricDefinitionDigest",
                metric.get("metricDefinitionDigest"),
                seen_metric_digests,
            ),
        ):
            if not isinstance(value, str):
                errors.append(f"{metric_label}.{field}: expected identifier")
                continue
            if value in seen:
                errors.append(f"{metric_label}.{field}: duplicate identity")
            seen.add(value)
        source_roles = metric.get("sourceRoleAllowlist")
        _require_canonical_set_order(
            source_roles, f"{metric_label}.sourceRoleAllowlist", errors
        )
        source_role_set = {
            role
            for role in (source_roles if isinstance(source_roles, list) else [])
            if isinstance(role, str)
        }
        if not source_role_set.issubset(required_role_set):
            errors.append(f"{metric_label}.sourceRoleAllowlist: outside vocabulary")
        exact_projection = metric.get("exactValueProjection")
        if isinstance(exact_projection, Mapping):
            source_ref = exact_projection.get("sourceSchemaRef")
            source_path = source_ref.split("#", 1)[0] if isinstance(source_ref, str) else None
            source_schema = _worktree_bytes(
                root, source_path, f"{metric_label}.sourceSchemaRef", errors
            )
            _check_blob_hash(
                source_schema,
                exact_projection.get("sourceSchemaSha256"),
                f"{metric_label}.sourceSchema",
                errors,
            )
        value_contract = metric.get("valueContract")
        if isinstance(value_contract, Mapping):
            lower = (
                _decimal_fraction(
                    value_contract.get("minimumInclusiveOrNull"),
                    f"{metric_label}.valueContract.minimumInclusiveOrNull",
                    errors,
                )
                if value_contract.get("minimumInclusiveOrNull") is not None
                else None
            )
            upper = (
                _decimal_fraction(
                    value_contract.get("maximumInclusiveOrNull"),
                    f"{metric_label}.valueContract.maximumInclusiveOrNull",
                    errors,
                )
                if value_contract.get("maximumInclusiveOrNull") is not None
                else None
            )
            if lower is not None and upper is not None and lower > upper:
                errors.append(f"{metric_label}.valueContract: inverted bounds")
            minimum_samples = value_contract.get("minimumSampleCount")
            maximum_samples = value_contract.get("maximumSampleCount")
            if (
                isinstance(minimum_samples, int)
                and isinstance(maximum_samples, int)
                and maximum_samples < minimum_samples
            ):
                errors.append(f"{metric_label}.valueContract: inverted sample bounds")
    return definition


def _qualification_request_nonce_digest(
    value: Any, label: str, errors: list[str]
) -> str | None:
    if not isinstance(value, str):
        errors.append(f"{label}: expected unpadded base64url")
        return None
    try:
        decoded = base64.b64decode(
            value + ("=" * ((-len(value)) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, base64.binascii.Error) as exc:
        errors.append(f"{label}: invalid base64url: {exc}")
        return None
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != value:
        errors.append(f"{label}: non-canonical base64url encoding")
    if len(decoded) < 16:
        errors.append(f"{label}: fewer than 128 bits")
    return sha256(
        b"QMAN-DIRECTPATH/QUALIFICATION-RUN-NONCE/V1\x00"
        + canonical.encode("ascii")
    )


def _validate_qualification_run_request(
    descriptor: Any,
    *,
    run: Mapping[str, Any],
    subject: Mapping[str, Any],
    record: Mapping[str, Any],
    code_git: _GitView | None,
    evidence_git: _GitView | None,
    root: Path,
    mapping: Mapping[str, Any] | None,
    trust: _TrustContext | None,
    label: str,
    errors: list[str],
) -> tuple[Mapping[str, Any] | None, Mapping[str, Any] | None]:
    schema_ref = "contracts/directpath-qualification-run-request.schema.json"
    _blob, request = _resolve_pinned_json_descriptor(
        descriptor,
        expected_schema_ref=schema_ref,
        evidence_git=evidence_git,
        root=root,
        label=label,
        errors=errors,
    )
    if not isinstance(descriptor, Mapping) or not isinstance(request, Mapping):
        return None, None
    request_key = _verify_history_signed_envelope(
        request,
        digest_field="requestDigest",
        signature_field="signature",
        signer_field="signerKeyId",
        signed_time_field="issuedAt",
        domain="QMAN-DIRECTPATH/QUALIFICATION-RUN-REQUEST/V1",
        required_role="TEST_EVIDENCE",
        trust=trust,
        evidence_git=evidence_git,
        root=root,
        label=label,
        errors=errors,
    )
    if descriptor.get("requestDigest") != request.get("requestDigest"):
        errors.append(f"{label}.requestDigest: parsed request mismatch")
    descriptor_fields = (
        "orchestratorId",
        "orchestratorPrincipalId",
        "requestId",
        "requestNonce",
        "issuedAt",
        "expiresAt",
    )
    for field in descriptor_fields:
        if descriptor.get(field) != request.get(field):
            errors.append(f"{label}.{field}: parsed request mismatch")
    if isinstance(request_key, Mapping) and request_key.get(
        "principalId"
    ) != request.get("orchestratorPrincipalId"):
        errors.append(f"{label}.orchestratorPrincipalId: signer principal mismatch")

    current_snapshot = run.get("currentInventorySnapshot")
    platform = run.get("platformProfile")
    backend = run.get("backendProfile")
    workload = run.get("workloadResult")
    expected_request = {
        "qualificationRunId": run.get("qualificationRunId"),
        "targetRepositoryCommit": run.get("targetRepositoryCommit"),
        "mappingCoreId": run.get("mappingCoreId"),
        "mappingCoreDigest": run.get("mappingCoreDigest"),
        "portableContractSha256": run.get("portableContractSha256"),
        "hostId": run.get("hostId"),
        "hostEpoch": run.get("hostEpoch"),
        "bootId": run.get("bootId"),
        "deviceUid": run.get("deviceUid"),
        "deviceRecordHash": run.get("deviceRecordHash"),
        "currentInventorySnapshotDigest": (
            current_snapshot.get("inventorySnapshotDigest")
            if isinstance(current_snapshot, Mapping)
            else None
        ),
        "platformProfileId": (
            platform.get("platformProfileId")
            if isinstance(platform, Mapping)
            else None
        ),
        "platformProfileDigest": (
            platform.get("platformProfileDigest")
            if isinstance(platform, Mapping)
            else None
        ),
        "backendFamily": (
            backend.get("backendFamily") if isinstance(backend, Mapping) else None
        ),
        "configuredIommuType": (
            backend.get("configuredIommuType")
            if isinstance(backend, Mapping)
            else None
        ),
        "backendProfileDigest": (
            backend.get("backendProfileDigest")
            if isinstance(backend, Mapping)
            else None
        ),
        "workloadId": (
            workload.get("workloadId") if isinstance(workload, Mapping) else None
        ),
        "workloadDefinitionDigest": (
            workload.get("workloadDefinitionDigest")
            if isinstance(workload, Mapping)
            else None
        ),
        "minimumDurationSeconds": (
            record.get("guestDriverAndWorkload", {}).get(
                "minimumDurationSeconds"
            )
            if isinstance(record.get("guestDriverAndWorkload"), Mapping)
            else None
        ),
        "requestedCaseIds": subject.get("caseIds"),
    }
    for field, expected in expected_request.items():
        if field == "targetRepositoryCommit":
            actual_normalized = _normal_commit(
                request.get(field), f"{label}.{field}", errors
            )
            expected_normalized = _normal_commit(
                expected, f"{label}.run.{field}", errors
            )
            mismatched = actual_normalized != expected_normalized
        else:
            mismatched = request.get(field) != expected
        if mismatched:
            errors.append(f"{label}.{field}: QualificationRun plan mismatch")
    _qualification_request_nonce_digest(
        request.get("requestNonce"), f"{label}.requestNonce", errors
    )
    _require_canonical_set_order(
        request.get("requestedCaseIds"), f"{label}.requestedCaseIds", errors
    )
    issued = _parse_time(request.get("issuedAt"), f"{label}.issuedAt", errors)
    expires = _parse_time(request.get("expiresAt"), f"{label}.expiresAt", errors)
    run_started = _parse_time(run.get("startedAt"), f"{label}.run.startedAt", errors)
    run_finished = _parse_time(run.get("finishedAt"), f"{label}.run.finishedAt", errors)
    if issued is not None and expires is not None and issued >= expires:
        errors.append(f"{label}: issuedAt must strictly precede expiresAt")
    if issued is not None and run_started is not None and issued >= run_started:
        errors.append(f"{label}: request must precede run start")
    if expires is not None and run_finished is not None and run_finished > expires:
        errors.append(f"{label}: run finishes after request expiry")
    definition = _validate_qualification_workload_definition(
        request.get("workloadDefinition"),
        request=request,
        subject=subject,
        record=record,
        code_git=code_git,
        evidence_git=evidence_git,
        root=root,
        mapping=mapping,
        trust=trust,
        label=f"{label}.workloadDefinition",
        errors=errors,
    )
    return request, definition


_DECIMAL_VALUE_RE = re.compile(
    r"^(?P<sign>-?)(?P<integer>0|[1-9][0-9]*)"
    r"(?:\.(?P<fraction>[0-9]+))?$"
)
_MAX_METRIC_INPUT_BYTES = 128
_MAX_METRIC_COEFFICIENT_DIGITS = 128
_MAX_METRIC_FRACTIONAL_DIGITS = 127
_MAX_METRIC_SAMPLES = 1_000_000
_MAX_METRIC_WORKING_COEFFICIENT_DIGITS = 256


def _decimal_fraction(
    value: Any, label: str, errors: list[str]
) -> Fraction | None:
    if not isinstance(value, str):
        errors.append(f"{label}: expected a decimal string")
        return None
    match = _DECIMAL_VALUE_RE.fullmatch(value)
    if match is None:
        errors.append(f"{label}: invalid canonical decimal string")
        return None
    if len(value.encode("utf-8")) > _MAX_METRIC_INPUT_BYTES:
        errors.append(f"{label}: encoded decimal exceeds 128 bytes")
        return None
    fraction_digits = match.group("fraction") or ""
    if len(fraction_digits) > _MAX_METRIC_FRACTIONAL_DIGITS:
        errors.append(f"{label}: fractional scale exceeds signed limit 127")
        return None
    coefficient_text = match.group("integer") + fraction_digits
    if len(coefficient_text) > _MAX_METRIC_COEFFICIENT_DIGITS:
        errors.append(f"{label}: coefficient exceeds signed limit 128 digits")
        return None
    try:
        coefficient = int(coefficient_text)
    except ValueError:
        errors.append(f"{label}: decimal coefficient cannot be represented safely")
        return None
    if match.group("sign") == "-":
        coefficient = -coefficient
    return Fraction(coefficient, 10 ** len(fraction_digits))


def _decimal_samples(
    value: Any, label: str, errors: list[str]
) -> list[Fraction]:
    values = value if isinstance(value, list) else [value]
    if len(values) > _MAX_METRIC_SAMPLES:
        errors.append(f"{label}: sample count exceeds signed limit 1000000")
        return []
    samples: list[Fraction] = []
    for number, item in enumerate(values):
        parsed = _decimal_fraction(item, f"{label}[{number}]", errors)
        if parsed is not None:
            samples.append(parsed)
    return samples


def _aggregate_metric_samples(
    samples: Sequence[Fraction],
    aggregation: Any,
    output_scale: Any,
    window_duration_nanoseconds: int | None,
    label: str,
    errors: list[str],
) -> str | None:
    if not samples:
        errors.append(f"{label}: cannot aggregate an empty sample set")
        return None
    if not isinstance(output_scale, int) or isinstance(output_scale, bool):
        errors.append(f"{label}.outputScale: expected non-negative integer")
        return None
    if len(samples) > _MAX_METRIC_SAMPLES:
        errors.append(f"{label}: sample count exceeds signed limit 1000000")
        return None
    if aggregation == "INSTANT":
        if len(samples) != 1:
            errors.append(f"{label}: INSTANT requires exactly one sample")
            return None
        value = samples[0]
    elif aggregation == "MIN":
        value = min(samples)
    elif aggregation == "MAX":
        value = max(samples)
    elif aggregation == "TOTAL":
        value = sum(samples, Fraction(0))
    elif aggregation == "MEAN":
        value = sum(samples, Fraction(0)) / len(samples)
    elif aggregation in {"P50", "P95", "P99"}:
        percentile = int(str(aggregation)[1:])
        ordered = sorted(samples)
        rank = (percentile * len(ordered) + 99) // 100
        value = ordered[rank - 1]
    elif aggregation == "RATE":
        if (
            not isinstance(window_duration_nanoseconds, int)
            or window_duration_nanoseconds <= 0
        ):
            errors.append(f"{label}: RATE requires a positive monotonic window")
            return None
        value = (
            sum(samples, Fraction(0))
            * 1_000_000_000
            / window_duration_nanoseconds
        )
    else:
        errors.append(f"{label}.aggregation: unsupported metric aggregation")
        return None
    if len(str(abs(value.numerator))) > _MAX_METRIC_WORKING_COEFFICIENT_DIGITS or len(
        str(value.denominator)
    ) > _MAX_METRIC_WORKING_COEFFICIENT_DIGITS:
        errors.append(f"{label}: exact intermediate exceeds signed 256-digit limit")
        return None
    scaled = value * (10**output_scale)
    sign = -1 if scaled < 0 else 1
    numerator = abs(scaled.numerator)
    denominator = scaled.denominator
    quotient, remainder = divmod(numerator, denominator)
    doubled = remainder * 2
    if doubled > denominator or (doubled == denominator and quotient % 2 == 1):
        quotient += 1
    rounded_scaled = sign * quotient
    if rounded_scaled == 0:
        sign_text = ""
    else:
        sign_text = "-" if rounded_scaled < 0 else ""
    digits = str(abs(rounded_scaled))
    if output_scale == 0:
        return sign_text + digits
    digits = digits.zfill(output_scale + 1)
    return sign_text + digits[:-output_scale] + "." + digits[-output_scale:]


_REPLAY_CLOSURE_ENTRY_FIELDS = {
    "role",
    "repository",
    "path",
    "sha256",
    "byteLength",
    "mediaType",
    "modeOrNull",
    "readOnly",
    "bytes",
}
_REPLAY_INPUT_FIELDS = {
    "role",
    "sourcePathOrNull",
    "schemaRef",
    "schemaSha256",
    "sha256",
    "byteLength",
    "mediaType",
    "readOnly",
    "bytes",
}
_REPLAY_OBSERVATION_ARTIFACT_FIELDS = {
    "observationId",
    "artifactRole",
    "observedAt",
    "path",
    "sha256",
    "byteLength",
    "mediaType",
    "schemaRefOrNull",
    "schemaSha256OrNull",
    "valueProjectionOrNull",
    "readOnly",
    "bytes",
}
_REPLAY_RESPONSE_FIELDS = {
    "protocol",
    "requestDigest",
    "consumerKind",
    "targetArchitecture",
    "exitCode",
    "outputBytes",
    "outputSha256",
    "attestation",
}
_REPLAY_ATTESTATION_FIELDS = {
    "protocol",
    "runnerId",
    "requestDigest",
    "consumerKind",
    "targetArchitecture",
    "targetRepositoryCommit",
    "mappingCoreId",
    "portableContractSha256",
    "consumerArtifactDigest",
    "interfaceContractDigest",
    "closureDigest",
    "inputSetDigest",
    "evidenceRootArtifactSetDigest",
    "outputContractDigest",
    "isolationPolicyDigest",
    "enforcedPolicy",
    "exitCode",
    "outputSha256",
    "attestationBytes",
    "attestationSha256",
}


def _replay_entry_projection(entry: Mapping[str, Any]) -> dict[str, Any]:
    """Return the request-digest projection, excluding only immutable bytes."""

    return {key: copy.deepcopy(value) for key, value in entry.items() if key != "bytes"}


def _collect_source_replay_closure(
    *,
    descriptor: Mapping[str, Any],
    code_git: _GitView,
    evidence_git: _GitView,
    label: str,
    errors: list[str],
    path_prefix: str = "",
    depth: int = 0,
    budget: list[int] | None = None,
    seen: set[tuple[str, str]] | None = None,
) -> list[dict[str, Any]]:
    """Materialize the already-validated recursive source tree from Git objects."""

    if depth > 16:
        errors.append(f"{label}: replay source-tree depth exceeds 16")
        return []
    remaining = budget if budget is not None else [256]
    identities = seen if seen is not None else set()
    if code_git.path is None or code_git.commit is None:
        errors.append(f"{label}: pinned source repository is unavailable")
        return []
    identity = (str(code_git.path), code_git.commit)
    if identity in identities:
        errors.append(f"{label}: replay source-tree cycle")
        return []
    identities = {*identities, identity}

    manifest_blob = evidence_git.blob(
        descriptor.get("path"), f"{label}.path", errors
    )
    _check_blob_hash(manifest_blob, descriptor.get("sha256"), label, errors)
    if manifest_blob is None:
        return []
    if isinstance(descriptor.get("byteLength"), int) and descriptor.get(
        "byteLength"
    ) != len(manifest_blob):
        errors.append(f"{label}.byteLength: source-tree manifest mismatch")
    manifest = _load_json_bytes(manifest_blob, label, errors)
    if not isinstance(manifest, Mapping):
        return []
    closure: list[dict[str, Any]] = [
        {
            "role": f"sourceTreeManifest:{path_prefix or '.'}",
            "repository": "EVIDENCE_REPOSITORY",
            "path": descriptor.get("path"),
            "sha256": sha256(manifest_blob),
            "byteLength": len(manifest_blob),
            "mediaType": "application/json",
            "modeOrNull": None,
            "readOnly": True,
            "bytes": manifest_blob,
        }
    ]

    submodules = {
        item.get("path"): item
        for item in manifest.get("submoduleTrees", [])
        if isinstance(item, Mapping) and isinstance(item.get("path"), str)
    }
    for number, entry in enumerate(manifest.get("entries", [])):
        entry_label = f"{label}.entries[{number}]"
        if not isinstance(entry, Mapping):
            continue
        path = entry.get("path")
        mode = entry.get("mode")
        object_id = entry.get("gitObjectId")
        if not isinstance(path, str) or not isinstance(object_id, str):
            errors.append(f"{entry_label}: incomplete source entry")
            continue
        complete_path = f"{path_prefix}{path}"
        if mode == "160000":
            gitlink_bytes = object_id.encode("ascii", errors="strict")
            if (
                entry.get("contentSha256") != sha256(gitlink_bytes)
                or entry.get("byteLength") != len(gitlink_bytes)
            ):
                errors.append(f"{entry_label}: gitlink content mismatch")
            closure.append(
                {
                    "role": f"sourceGitlink:{complete_path}",
                    "repository": "TARGET_REPOSITORY",
                    "path": complete_path,
                    "sha256": sha256(gitlink_bytes),
                    "byteLength": len(gitlink_bytes),
                    "mediaType": "application/vnd.git.gitlink",
                    "modeOrNull": mode,
                    "readOnly": True,
                    "bytes": gitlink_bytes,
                }
            )
            submodule = submodules.get(path)
            if not isinstance(submodule, Mapping):
                errors.append(f"{entry_label}: submodule manifest is unavailable")
                continue
            if remaining[0] <= 0:
                errors.append(f"{label}: replay source-tree count exceeds 256")
                continue
            remaining[0] -= 1
            try:
                submodule_path = code_git.path.joinpath(
                    *PurePosixPath(path).parts
                ).resolve(strict=True)
                submodule_path.relative_to(code_git.path.resolve(strict=True))
            except (OSError, ValueError) as exc:
                errors.append(f"{entry_label}: submodule checkout unavailable: {exc}")
                continue
            commit = submodule.get("commit")
            sub_git = _GitView(
                code_git.path,
                {
                    "repositoryLocation": str(submodule_path),
                    "objectFormat": (
                        "SHA1" if isinstance(commit, str) and len(commit) == 40 else "SHA256"
                    ),
                    "commit": commit,
                },
                errors,
                f"{entry_label}.repository",
            )
            closure.extend(
                _collect_source_replay_closure(
                    descriptor={
                        "path": submodule.get("manifestPath"),
                        "sha256": submodule.get("manifestSha256"),
                    },
                    code_git=sub_git,
                    evidence_git=evidence_git,
                    label=f"{entry_label}.sourceTree",
                    errors=errors,
                    path_prefix=f"{complete_path}/",
                    depth=depth + 1,
                    budget=remaining,
                    seen=identities,
                )
            )
            continue
        if mode not in {"100644", "100755", "120000"}:
            errors.append(f"{entry_label}.mode: unsupported source entry")
            continue
        source_blob = code_git._run(["cat-file", "blob", object_id])
        if source_blob is None:
            errors.append(f"{entry_label}: cannot resolve pinned Git blob")
            continue
        _check_blob_hash(
            source_blob, entry.get("contentSha256"), entry_label, errors
        )
        if entry.get("byteLength") != len(source_blob):
            errors.append(f"{entry_label}.byteLength: pinned Git blob mismatch")
        closure.append(
            {
                "role": f"source:{complete_path}",
                "repository": "TARGET_REPOSITORY",
                "path": complete_path,
                "sha256": sha256(source_blob),
                "byteLength": len(source_blob),
                "mediaType": "application/octet-stream",
                "modeOrNull": mode,
                "readOnly": True,
                "bytes": source_blob,
            }
        )
    return closure


def _collect_consumer_replay_closure(
    *,
    consumer_kind: str,
    manifest_descriptor: Mapping[str, Any],
    manifest: Mapping[str, Any],
    consumer_build_id: Any,
    code_git: _GitView | None,
    evidence_git: _GitView | None,
    root: Path,
    trust: _TrustContext | None,
    label: str,
    errors: list[str],
) -> tuple[list[dict[str, Any]], str | None]:
    """Resolve every byte that the trusted isolation runner may expose."""

    if code_git is None or evidence_git is None:
        errors.append(f"{label}: pinned C and E repositories are required for replay")
        return [], None
    source_tree = manifest.get("sourceTree")
    build_bundle = _validate_build_attestation(
        manifest.get("buildAttestation"),
        expected_consumer_kind=consumer_kind,
        expected_consumer_build_id=consumer_build_id,
        expected_target_commit=manifest.get("targetRepositoryCommit"),
        expected_mapping_core_id=manifest.get("mappingCoreId"),
        expected_portable_contract_sha256=manifest.get("portableContractSha256"),
        expected_source_tree=(
            dict(source_tree) if isinstance(source_tree, Mapping) else None
        ),
        code_git=code_git,
        evidence_git=evidence_git,
        root=root,
        trust=trust,
        label=f"{label}.buildAttestation",
        errors=errors,
    )
    if not isinstance(build_bundle, Mapping):
        errors.append(f"{label}: complete signed build closure is unavailable")
        return [], None
    attestation = build_bundle.get("attestation")
    artifacts = build_bundle.get("artifacts")
    if not isinstance(attestation, Mapping) or not isinstance(artifacts, Mapping):
        errors.append(f"{label}: parsed BuildAttestation closure is unavailable")
        return [], None
    for number, external in enumerate(attestation.get("declaredExternalInputs", [])):
        if isinstance(external, Mapping) and external.get("availability") != "ARCHIVED_BYTES":
            errors.append(
                f"{label}.buildAttestation.declaredExternalInputs[{number}]: "
                "hash-only input makes deterministic replay impossible"
            )

    closure: list[dict[str, Any]] = []
    manifest_blob = evidence_git.blob(
        manifest_descriptor.get("path"), f"{label}.manifest.path", errors
    )
    _check_blob_hash(
        manifest_blob, manifest_descriptor.get("sha256"), f"{label}.manifest", errors
    )
    if manifest_blob is not None:
        if manifest_descriptor.get("byteLength") != len(manifest_blob):
            errors.append(f"{label}.manifest.byteLength: raw manifest mismatch")
        closure.append(
            {
                "role": "consumerManifest",
                "repository": "EVIDENCE_REPOSITORY",
                "path": manifest_descriptor.get("path"),
                "sha256": sha256(manifest_blob),
                "byteLength": len(manifest_blob),
                "mediaType": "application/json",
                "modeOrNull": None,
                "readOnly": True,
                "bytes": manifest_blob,
            }
        )
    build_descriptor = manifest.get("buildAttestation")
    if isinstance(build_descriptor, Mapping):
        build_blob = evidence_git.blob(
            build_descriptor.get("path"), f"{label}.buildAttestation.path", errors
        )
        _check_blob_hash(
            build_blob,
            build_descriptor.get("sha256"),
            f"{label}.buildAttestation",
            errors,
        )
        if build_blob is not None:
            if build_descriptor.get("byteLength") != len(build_blob):
                errors.append(f"{label}.buildAttestation.byteLength: mismatch")
            closure.append(
                {
                    "role": "buildAttestation",
                    "repository": "EVIDENCE_REPOSITORY",
                    "path": build_descriptor.get("path"),
                    "sha256": sha256(build_blob),
                    "byteLength": len(build_blob),
                    "mediaType": "application/json",
                    "modeOrNull": None,
                    "readOnly": True,
                    "bytes": build_blob,
                }
            )
    if isinstance(source_tree, Mapping):
        closure.extend(
            _collect_source_replay_closure(
                descriptor=source_tree,
                code_git=code_git,
                evidence_git=evidence_git,
                label=f"{label}.sourceTree",
                errors=errors,
            )
        )
    else:
        errors.append(f"{label}.sourceTree: complete source closure is unavailable")
    for role, descriptor in artifacts.items():
        if not isinstance(role, str) or not isinstance(descriptor, Mapping):
            continue
        blob = evidence_git.blob(
            descriptor.get("path"), f"{label}.{role}.path", errors
        )
        _check_blob_hash(blob, descriptor.get("sha256"), f"{label}.{role}", errors)
        if blob is None:
            continue
        if descriptor.get("byteLength") != len(blob):
            errors.append(f"{label}.{role}.byteLength: raw closure mismatch")
        closure.append(
            {
                "role": f"buildArtifact:{role}",
                "repository": "EVIDENCE_REPOSITORY",
                "path": descriptor.get("path"),
                "sha256": sha256(blob),
                "byteLength": len(blob),
                "mediaType": descriptor.get("mediaType"),
                "modeOrNull": None,
                "readOnly": True,
                "bytes": blob,
            }
        )
    closure.sort(key=lambda item: str(item.get("role", "")).encode("utf-8"))
    roles = [item.get("role") for item in closure]
    if len(roles) != len(set(roles)):
        errors.append(f"{label}: replay closure roles are not unique")
    environment = attestation.get("environment")
    architecture = (
        environment.get("architecture") if isinstance(environment, Mapping) else None
    )
    if architecture not in {"x86_64", "aarch64", "c86", "other"}:
        errors.append(f"{label}.targetArchitecture: unavailable from BuildAttestation")
        architecture = None
    return closure, architecture


def _execute_signed_artifact_replay(
    *,
    consumer_kind: str,
    consumer_protocol: Any,
    consumer_artifact_digest: Any,
    consumer_manifest_descriptor: Mapping[str, Any],
    interface_contract_digest: Any,
    target_repository_commit: Any,
    mapping_core_id: Any,
    portable_contract_sha256: Any,
    target_architecture: str | None,
    runtime_identity: Mapping[str, Any],
    closure: list[dict[str, Any]],
    inputs: list[dict[str, Any]],
    evidence_root_artifacts: list[dict[str, Any]],
    semantic_argv_order: list[str],
    output_role: str,
    output_schema_ref: str,
    output_schema_sha256: Any,
    expected_output: Mapping[str, Any],
    root: Path,
    label: str,
    errors: list[str],
) -> None:
    """Replay via a verifier-owned isolation hook; never execute artifact bytes here."""

    entry_error_count = len(errors)
    hook = _SIGNED_ARTIFACT_REPLAY_HOOK
    if hook is None:
        errors.append(
            f"{label}: final {consumer_kind} artifact requires a configured trusted "
            "signed-artifact isolation replay hook"
        )
        return
    if target_architecture is None:
        errors.append(f"{label}: target architecture is unavailable")
        return
    for number, entry in enumerate(closure):
        entry_label = f"{label}.closure[{number}]"
        _exact_keys(entry, _REPLAY_CLOSURE_ENTRY_FIELDS, entry_label, errors)
        blob = entry.get("bytes")
        if not isinstance(blob, bytes):
            errors.append(f"{entry_label}.bytes: expected immutable bytes")
            continue
        if entry.get("sha256") != sha256(blob):
            errors.append(f"{entry_label}.sha256: raw closure mismatch")
        if entry.get("byteLength") != len(blob):
            errors.append(f"{entry_label}.byteLength: raw closure mismatch")
        if entry.get("readOnly") is not True:
            errors.append(f"{entry_label}.readOnly: must be true")
    for number, entry in enumerate(inputs):
        entry_label = f"{label}.inputs[{number}]"
        _exact_keys(entry, _REPLAY_INPUT_FIELDS, entry_label, errors)
        blob = entry.get("bytes")
        if not isinstance(blob, bytes):
            errors.append(f"{entry_label}.bytes: expected immutable bytes")
            continue
        if entry.get("sha256") != sha256(blob):
            errors.append(f"{entry_label}.sha256: raw input mismatch")
        if entry.get("byteLength") != len(blob):
            errors.append(f"{entry_label}.byteLength: raw input mismatch")
        if entry.get("readOnly") is not True:
            errors.append(f"{entry_label}.readOnly: must be true")
    observation_paths: list[str] = []
    observation_hashes: list[str] = []
    for number, entry in enumerate(evidence_root_artifacts):
        entry_label = f"{label}.evidenceRootArtifacts[{number}]"
        _exact_keys(
            entry,
            _REPLAY_OBSERVATION_ARTIFACT_FIELDS,
            entry_label,
            errors,
        )
        blob = entry.get("bytes")
        if not isinstance(blob, bytes):
            errors.append(f"{entry_label}.bytes: expected immutable bytes")
            continue
        if entry.get("sha256") != sha256(blob):
            errors.append(f"{entry_label}.sha256: raw observation mismatch")
        if entry.get("byteLength") != len(blob):
            errors.append(f"{entry_label}.byteLength: raw observation mismatch")
        if entry.get("readOnly") is not True:
            errors.append(f"{entry_label}.readOnly: must be true")
        path = entry.get("path")
        digest = entry.get("sha256")
        if isinstance(path, str):
            observation_paths.append(path)
        if isinstance(digest, str):
            observation_hashes.append(digest)
    if len(observation_paths) != len(set(observation_paths)):
        errors.append(f"{label}.evidenceRootArtifacts: duplicate descriptor path")
    if len(observation_hashes) != len(set(observation_hashes)):
        errors.append(f"{label}.evidenceRootArtifacts: duplicate descriptor hash")
    input_roles = [entry.get("role") for entry in inputs]
    semantic_input_roles = [
        role for role in semantic_argv_order if role not in {"evidenceRoot", "output"}
    ]
    if input_roles != semantic_input_roles or len(input_roles) != len(
        set(input_roles)
    ):
        errors.append(f"{label}.inputs: exact semantic argv order mismatch")

    closure_projection = [_replay_entry_projection(item) for item in closure]
    input_projection = [_replay_entry_projection(item) for item in inputs]
    evidence_root_projection = [
        _replay_entry_projection(item) for item in evidence_root_artifacts
    ]
    output_contract = {
        "role": output_role,
        "schemaRef": output_schema_ref,
        "schemaSha256": output_schema_sha256,
        "mediaType": "application/json",
        "exclusiveNewOutput": True,
        "maximumByteLength": _SIGNED_ARTIFACT_REPLAY_POLICY["limits"][
            "maximumOutputBytes"
        ],
    }
    closure_digest = _domain_projection_digest(
        "QMAN-DIRECTPATH/SIGNED-ARTIFACT-REPLAY/CLOSURE/V1",
        closure_projection,
        f"{label}.closureDigest",
        errors,
    )
    input_set_digest = _domain_projection_digest(
        "QMAN-DIRECTPATH/SIGNED-ARTIFACT-REPLAY/INPUT-SET/V1",
        input_projection,
        f"{label}.inputSetDigest",
        errors,
    )
    evidence_root_artifact_set_digest = _domain_projection_digest(
        "QMAN-DIRECTPATH/SIGNED-ARTIFACT-REPLAY/EVIDENCE-ROOT-ARTIFACT-SET/V1",
        evidence_root_projection,
        f"{label}.evidenceRootArtifactSetDigest",
        errors,
    )
    output_contract_digest = _domain_projection_digest(
        "QMAN-DIRECTPATH/SIGNED-ARTIFACT-REPLAY/OUTPUT-CONTRACT/V1",
        output_contract,
        f"{label}.outputContractDigest",
        errors,
    )
    isolation_policy = copy.deepcopy(_SIGNED_ARTIFACT_REPLAY_POLICY)
    isolation_policy_digest = _domain_projection_digest(
        "QMAN-DIRECTPATH/SIGNED-ARTIFACT-REPLAY/ISOLATION-POLICY/V1",
        isolation_policy,
        f"{label}.isolationPolicyDigest",
        errors,
    )
    metadata = {
        "protocol": _SIGNED_ARTIFACT_REPLAY_PROTOCOL,
        "consumerKind": consumer_kind,
        "consumerProtocol": consumer_protocol,
        "consumerArtifact": {
            "path": consumer_manifest_descriptor.get("path"),
            "rawSha256": consumer_manifest_descriptor.get("sha256"),
            "byteLength": consumer_manifest_descriptor.get("byteLength"),
            "internalDigest": consumer_artifact_digest,
        },
        "interfaceContractDigest": interface_contract_digest,
        "targetRepositoryCommit": target_repository_commit,
        "mappingCoreId": mapping_core_id,
        "portableContractSha256": portable_contract_sha256,
        "targetArchitecture": target_architecture,
        "runtimeIdentity": copy.deepcopy(dict(runtime_identity)),
        "semanticArgvOrder": copy.deepcopy(semantic_argv_order),
        "environment": {"LC_ALL": "C.UTF-8", "TZ": "UTC"},
        "closure": closure_projection,
        "closureDigest": closure_digest,
        "inputs": input_projection,
        "inputSetDigest": input_set_digest,
        "evidenceRootArtifacts": evidence_root_projection,
        "evidenceRootArtifactSetDigest": evidence_root_artifact_set_digest,
        "outputContract": output_contract,
        "outputContractDigest": output_contract_digest,
        "isolationPolicy": isolation_policy,
        "isolationPolicyDigest": isolation_policy_digest,
    }
    request_digest = _domain_projection_digest(
        "QMAN-DIRECTPATH/SIGNED-ARTIFACT-REPLAY/REQUEST/V1",
        metadata,
        f"{label}.requestDigest",
        errors,
    )
    if request_digest is None:
        return
    if entry_error_count != 0 or len(errors) != entry_error_count:
        errors.append(
            f"{label}: signed-artifact replay preflight is invalid; trusted "
            "isolation hook was not invoked"
        )
        return
    request_for_hook = copy.deepcopy(metadata)
    request_for_hook["requestDigest"] = request_digest
    request_for_hook["closure"] = copy.deepcopy(closure)
    request_for_hook["inputs"] = copy.deepcopy(inputs)
    request_for_hook["evidenceRootArtifacts"] = copy.deepcopy(
        evidence_root_artifacts
    )
    # The request digest intentionally binds byte descriptors rather than
    # embedding potentially large blobs.  Keep an exact in-memory snapshot as
    # well so a hook cannot replace only ``bytes`` while leaving the bound
    # descriptor/hash projection untouched.
    bound_request_snapshot = copy.deepcopy(request_for_hook)
    try:
        response = hook(request_for_hook)
    except Exception as exc:  # The configured trust adapter owns its exception types.
        errors.append(
            f"{label}: trusted isolation replay hook failed: {type(exc).__name__}: {exc}"
        )
        return
    post_hook_metadata = {
        key: copy.deepcopy(value)
        for key, value in request_for_hook.items()
        if key != "requestDigest"
    }
    post_hook_metadata["closure"] = [
        _replay_entry_projection(item)
        for item in request_for_hook.get("closure", [])
        if isinstance(item, Mapping)
    ]
    post_hook_metadata["inputs"] = [
        _replay_entry_projection(item)
        for item in request_for_hook.get("inputs", [])
        if isinstance(item, Mapping)
    ]
    post_hook_metadata["evidenceRootArtifacts"] = [
        _replay_entry_projection(item)
        for item in request_for_hook.get("evidenceRootArtifacts", [])
        if isinstance(item, Mapping)
    ]
    post_hook_digest = _domain_projection_digest(
        "QMAN-DIRECTPATH/SIGNED-ARTIFACT-REPLAY/REQUEST/V1",
        post_hook_metadata,
        f"{label}.postHookRequestDigest",
        errors,
    )
    if (
        request_for_hook != bound_request_snapshot
        or post_hook_digest != request_digest
        or request_for_hook.get("requestDigest") != request_digest
    ):
        errors.append(f"{label}: replay hook mutated the bound request")

    _exact_keys(response, _REPLAY_RESPONSE_FIELDS, f"{label}.response", errors)
    if not isinstance(response, Mapping):
        return
    exact_response = {
        "protocol": _SIGNED_ARTIFACT_REPLAY_PROTOCOL,
        "requestDigest": request_digest,
        "consumerKind": consumer_kind,
        "targetArchitecture": target_architecture,
    }
    for field, expected in exact_response.items():
        if response.get(field) != expected:
            errors.append(f"{label}.response.{field}: replay request mismatch")
    exit_code = response.get("exitCode")
    if type(exit_code) is not int or exit_code != 0:
        errors.append(
            f"{label}.response.exitCode: expected integer deterministic exit 0"
        )
    output_bytes = response.get("outputBytes")
    if not isinstance(output_bytes, bytes):
        errors.append(f"{label}.response.outputBytes: expected immutable bytes")
        output_bytes = None
    if isinstance(output_bytes, bytes):
        if len(output_bytes) > output_contract["maximumByteLength"]:
            errors.append(f"{label}.response.outputBytes: exceeds bounded output")
            return
        if response.get("outputSha256") != sha256(output_bytes):
            errors.append(f"{label}.response.outputSha256: output bytes mismatch")

    attestation = response.get("attestation")
    _exact_keys(
        attestation, _REPLAY_ATTESTATION_FIELDS, f"{label}.attestation", errors
    )
    if isinstance(attestation, Mapping):
        exact_attestation = {
            "protocol": _SIGNED_ARTIFACT_ATTESTATION_PROTOCOL,
            "requestDigest": request_digest,
            "consumerKind": consumer_kind,
            "targetArchitecture": target_architecture,
            "targetRepositoryCommit": target_repository_commit,
            "mappingCoreId": mapping_core_id,
            "portableContractSha256": portable_contract_sha256,
            "consumerArtifactDigest": consumer_artifact_digest,
            "interfaceContractDigest": interface_contract_digest,
            "closureDigest": closure_digest,
            "inputSetDigest": input_set_digest,
            "evidenceRootArtifactSetDigest": evidence_root_artifact_set_digest,
            "outputContractDigest": output_contract_digest,
            "isolationPolicyDigest": isolation_policy_digest,
            "enforcedPolicy": isolation_policy,
            "exitCode": exit_code,
            "outputSha256": response.get("outputSha256"),
        }
        for field, expected in exact_attestation.items():
            if attestation.get(field) != expected:
                errors.append(f"{label}.attestation.{field}: replay claim mismatch")
        runner_id = attestation.get("runnerId")
        if not isinstance(runner_id, str) or not runner_id:
            errors.append(f"{label}.attestation.runnerId: expected trusted runner identity")
        attestation_bytes = attestation.get("attestationBytes")
        if not isinstance(attestation_bytes, bytes) or not attestation_bytes:
            errors.append(
                f"{label}.attestation.attestationBytes: expected verified signed bytes"
            )
        elif attestation.get("attestationSha256") != sha256(attestation_bytes):
            errors.append(f"{label}.attestation.attestationSha256: raw mismatch")

    if output_bytes is None:
        return
    output_document = _load_json_bytes(output_bytes, f"{label}.output", errors)
    if output_document is not None:
        _validate_closed_json_schema_instance(
            output_document, root, output_schema_ref, f"{label}.output", errors
        )
    try:
        expected_bytes = canonical_json_bytes(expected_output)
    except (CanonicalizationError, TypeError, ValueError) as exc:
        errors.append(f"{label}: cannot construct expected output bytes: {exc}")
        return
    if output_bytes != expected_bytes:
        errors.append(
            f"{label}: isolation replay output is not byte-equal to the "
            "deterministic signed-artifact construction projection"
        )


def _replay_workload_evaluator(
    *,
    report: Mapping[str, Any],
    request_descriptor: Any,
    request: Mapping[str, Any],
    definition: Mapping[str, Any],
    evaluator_manifest: Mapping[str, Any],
    code_git: _GitView | None,
    evidence_git: _GitView | None,
    root: Path,
    trust: _TrustContext | None,
    label: str,
    errors: list[str],
) -> None:
    """Replay the evaluator only through the verifier-owned isolation hook."""

    manifest_descriptor = report.get("evaluatorManifest")
    if not isinstance(manifest_descriptor, Mapping):
        errors.append(f"{label}.evaluatorManifest: descriptor is unavailable")
        return
    closure, architecture = _collect_consumer_replay_closure(
        consumer_kind="WORKLOAD_EVALUATOR",
        manifest_descriptor=manifest_descriptor,
        manifest=evaluator_manifest,
        consumer_build_id=evaluator_manifest.get("manifestId"),
        code_git=code_git,
        evidence_git=evidence_git,
        root=root,
        trust=trust,
        label=f"{label}.closure",
        errors=errors,
    )
    if evidence_git is None:
        errors.append(f"{label}: pinned evidence repository is unavailable")
        return
    input_specs = (
        (
            "definition",
            request.get("workloadDefinition"),
            "contracts/directpath-qualification-workload-definition.schema.json",
            definition,
        ),
        (
            "request",
            request_descriptor,
            "contracts/directpath-qualification-run-request.schema.json",
            request,
        ),
        (
            "observations",
            None,
            "contracts/directpath-workload-evaluation-report.schema.json"
            "#/$defs/artifactObservationSet",
            report.get("artifactObservations"),
        ),
        (
            "context",
            report.get("evaluationContext"),
            "contracts/directpath-workload-evaluation-report.schema.json"
            "#/$defs/evaluationContext",
            None,
        ),
    )
    inputs: list[dict[str, Any]] = []
    input_contracts = evaluator_manifest.get("inputContracts")
    input_contract_roles = {
        "definition": "workloadDefinition",
        "request": "runRequest",
        "observations": "artifactObservationSet",
        "context": "evaluationContext",
    }
    for role, descriptor, schema_ref, expected_document in input_specs:
        if descriptor is None:
            try:
                blob = canonical_json_bytes(expected_document)
            except (CanonicalizationError, TypeError, ValueError) as exc:
                errors.append(f"{label}.{role}: cannot construct JCS input: {exc}")
                continue
            document = expected_document
            source_path = None
        else:
            blob, document = _resolve_pinned_json_descriptor(
                descriptor,
                expected_schema_ref=schema_ref,
                evidence_git=evidence_git,
                root=root,
                label=f"{label}.{role}",
                errors=errors,
            )
            source_path = descriptor.get("path") if isinstance(descriptor, Mapping) else None
        if blob is None:
            continue
        if expected_document is not None and document != expected_document:
            errors.append(f"{label}.{role}: parsed input changed before replay")
        contract_role = input_contract_roles[role]
        contract = (
            input_contracts.get(contract_role)
            if isinstance(input_contracts, Mapping)
            else None
        )
        inputs.append(
            {
                "role": role,
                "sourcePathOrNull": source_path,
                "schemaRef": schema_ref,
                "schemaSha256": (
                    contract.get("schemaSha256")
                    if isinstance(contract, Mapping)
                    else None
                ),
                "sha256": sha256(blob),
                "byteLength": len(blob),
                "mediaType": "application/json",
                "readOnly": True,
                "bytes": blob,
            }
        )
    evidence_root_artifacts: list[dict[str, Any]] = []
    observations = report.get("artifactObservations")
    if not isinstance(observations, list):
        errors.append(f"{label}.artifactObservations: expected array")
        observations = []
    observed_paths: set[str] = set()
    observed_hashes: set[str] = set()
    observed_ids: set[str] = set()
    for number, observation in enumerate(observations):
        observation_label = f"{label}.artifactObservations[{number}]"
        if not isinstance(observation, Mapping):
            errors.append(f"{observation_label}: expected object")
            continue
        path = observation.get("path")
        digest = observation.get("sha256")
        observation_id = observation.get("observationId")
        for field, value, seen in (
            ("path", path, observed_paths),
            ("sha256", digest, observed_hashes),
            ("observationId", observation_id, observed_ids),
        ):
            if not isinstance(value, str):
                errors.append(f"{observation_label}.{field}: expected string")
            elif value in seen:
                errors.append(f"{observation_label}.{field}: duplicate identity")
            else:
                seen.add(value)
        blob = evidence_git.blob(path, f"{observation_label}.path", errors)
        _check_blob_hash(blob, digest, observation_label, errors)
        if blob is None:
            continue
        if observation.get("byteLength") != len(blob):
            errors.append(f"{observation_label}.byteLength: raw artifact mismatch")
        typed_tuple = (
            observation.get("schemaRefOrNull"),
            observation.get("schemaSha256OrNull"),
            observation.get("valueProjectionOrNull"),
        )
        if any(value is None for value in typed_tuple) and not all(
            value is None for value in typed_tuple
        ):
            errors.append(f"{observation_label}: typed projection tuple is partial")
        if all(isinstance(value, str) for value in typed_tuple):
            typed_ref, typed_digest, pointer = typed_tuple
            typed_schema = _worktree_bytes(
                root,
                typed_ref.split("#", 1)[0],
                f"{observation_label}.schemaRef",
                errors,
            )
            _check_blob_hash(
                typed_schema, typed_digest, f"{observation_label}.schema", errors
            )
            document = _load_json_bytes(blob, observation_label, errors)
            if document is not None:
                _validate_closed_json_schema_instance(
                    document, root, typed_ref, observation_label, errors
                )
                _json_pointer_projection(
                    document,
                    pointer,
                    f"{observation_label}.valueProjection",
                    errors,
                )
        evidence_root_artifacts.append(
            {
                **copy.deepcopy(dict(observation)),
                "readOnly": True,
                "bytes": blob,
            }
        )
    if len(evidence_root_artifacts) != len(observations):
        errors.append(
            f"{label}.artifactObservations: complete raw evidence-root closure is unavailable"
        )
    expected_report = copy.deepcopy(dict(report))
    expected_report["signedAt"] = None
    expected_report["reportDigest"] = None
    expected_report["signature"] = None
    evaluator = evaluator_manifest.get("evaluator")
    environment = evaluator_manifest.get("executionEnvironment")
    output_contract = evaluator_manifest.get("outputContract")
    if (
        not isinstance(evaluator, Mapping)
        or not isinstance(environment, Mapping)
        or not isinstance(output_contract, Mapping)
    ):
        errors.append(f"{label}: evaluator interface/runtime closure is unavailable")
        return
    runtime_binary = environment.get("runtimeBinary")
    runtime_identity = {
        "mode": environment.get("mode"),
        "runtimeBinarySha256": (
            runtime_binary.get("sha256")
            if isinstance(runtime_binary, Mapping)
            else None
        ),
        "dependencyLockSha256": (
            environment.get("dependencyLock", {}).get("sha256")
            if isinstance(environment.get("dependencyLock"), Mapping)
            else None
        ),
        "environmentManifestSha256": (
            environment.get("environmentManifest", {}).get("sha256")
            if isinstance(environment.get("environmentManifest"), Mapping)
            else None
        ),
    }
    _execute_signed_artifact_replay(
        consumer_kind="WORKLOAD_EVALUATOR",
        consumer_protocol=evaluator.get("protocol"),
        consumer_artifact_digest=evaluator_manifest.get("manifestDigest"),
        consumer_manifest_descriptor=manifest_descriptor,
        interface_contract_digest=evaluator.get("interfaceContractDigest"),
        target_repository_commit=evaluator_manifest.get("targetRepositoryCommit"),
        mapping_core_id=evaluator_manifest.get("mappingCoreId"),
        portable_contract_sha256=evaluator_manifest.get("portableContractSha256"),
        target_architecture=architecture,
        runtime_identity=runtime_identity,
        closure=closure,
        inputs=inputs,
        evidence_root_artifacts=evidence_root_artifacts,
        semantic_argv_order=[
            "definition",
            "request",
            "observations",
            "context",
            "evidenceRoot",
            "output",
        ],
        output_role="output",
        output_schema_ref="contracts/directpath-workload-evaluation-report.schema.json",
        output_schema_sha256=output_contract.get("schemaSha256"),
        expected_output=expected_report,
        root=root,
        label=label,
        errors=errors,
    )


def _validate_workload_evaluation_context(
    descriptor: Any,
    *,
    report: Mapping[str, Any],
    result: Mapping[str, Any],
    evidence_git: _GitView | None,
    root: Path,
    trust: _TrustContext | None,
    label: str,
    errors: list[str],
) -> Mapping[str, Any] | None:
    schema_ref = (
        "contracts/directpath-workload-evaluation-report.schema.json"
        "#/$defs/evaluationContext"
    )
    _blob, context = _resolve_pinned_json_descriptor(
        descriptor,
        expected_schema_ref=schema_ref,
        evidence_git=evidence_git,
        root=root,
        label=label,
        errors=errors,
    )
    if not isinstance(descriptor, Mapping) or not isinstance(context, Mapping):
        return None
    _verify_history_signed_envelope(
        context,
        digest_field="contextDigest",
        signature_field="signature",
        signer_field="signerKeyId",
        signed_time_field="evaluatedAt",
        domain="QMAN-DIRECTPATH/WORKLOAD-EVALUATION-CONTEXT/V1",
        required_role="TEST_EVIDENCE",
        trust=trust,
        evidence_git=evidence_git,
        root=root,
        label=label,
        errors=errors,
    )
    if descriptor.get("contextDigest") != context.get("contextDigest"):
        errors.append(f"{label}.contextDigest: parsed context mismatch")
    for field in (
        "evaluationId",
        "evaluatedAt",
        "keyRingVersion",
        "signerKeyId",
        "signerRole",
    ):
        if context.get(field) != report.get(field):
            errors.append(f"{label}.{field}: WorkloadEvaluationReport mismatch")
    evaluated_at = _parse_time(
        context.get("evaluatedAt"), f"{label}.evaluatedAt", errors
    )
    wall = result.get("wallClockTiming")
    workload_finished = (
        _parse_time(wall.get("finishedAt"), f"{label}.result.finishedAt", errors)
        if isinstance(wall, Mapping)
        else None
    )
    if (
        workload_finished is not None
        and evaluated_at is not None
        and evaluated_at < workload_finished
    ):
        errors.append(f"{label}.evaluatedAt: predates workload completion")
    return context


def _validate_workload_evaluation_report(
    descriptor: Any,
    *,
    result: Mapping[str, Any],
    request_descriptor: Any,
    request: Mapping[str, Any],
    definition: Mapping[str, Any],
    code_git: _GitView | None,
    evidence_git: _GitView | None,
    root: Path,
    mapping: Mapping[str, Any] | None,
    trust: _TrustContext | None,
    label: str,
    errors: list[str],
) -> Mapping[str, Any] | None:
    schema_ref = "contracts/directpath-workload-evaluation-report.schema.json"
    _blob, report = _resolve_pinned_json_descriptor(
        descriptor,
        expected_schema_ref=schema_ref,
        evidence_git=evidence_git,
        root=root,
        label=label,
        errors=errors,
    )
    if not isinstance(descriptor, Mapping) or not isinstance(report, Mapping):
        return None
    _verify_history_signed_envelope(
        report,
        digest_field="reportDigest",
        signature_field="signature",
        signer_field="signerKeyId",
        signed_time_field="signedAt",
        domain="QMAN-DIRECTPATH/WORKLOAD-EVALUATION-REPORT/V1",
        required_role="TEST_EVIDENCE",
        trust=trust,
        evidence_git=evidence_git,
        root=root,
        label=label,
        errors=errors,
    )
    for field in ("evaluationId", "reportDigest"):
        if descriptor.get(field) != report.get(field):
            errors.append(f"{label}.{field}: parsed report mismatch")
    descriptor_mirrors = {
        "evaluationOutcome": report.get("evaluationOutcome"),
        "evaluatedAt": report.get("evaluatedAt"),
        "reportSignedAt": report.get("signedAt"),
    }
    for field, expected in descriptor_mirrors.items():
        if descriptor.get(field) != expected:
            errors.append(f"{label}.{field}: parsed report mismatch")
    exact_report = {
        "qualificationRunId": request.get("qualificationRunId"),
        "qualificationRunRequestDigest": request.get("requestDigest"),
        "mappingCoreId": request.get("mappingCoreId"),
        "mappingCoreDigest": request.get("mappingCoreDigest"),
        "portableContractSha256": request.get("portableContractSha256"),
        "hostId": request.get("hostId"),
        "hostEpoch": request.get("hostEpoch"),
        "bootId": request.get("bootId"),
        "workloadId": definition.get("workloadId"),
        "workloadDefinitionDigest": definition.get("definitionDigest"),
        "evaluatorManifest": definition.get("evaluatorManifest"),
    }
    for field, expected in exact_report.items():
        if report.get(field) != expected:
            errors.append(f"{label}.{field}: request/definition mismatch")
    report_commit = _normal_commit(
        report.get("targetRepositoryCommit"),
        f"{label}.targetRepositoryCommit",
        errors,
    )
    request_commit = _normal_commit(
        request.get("targetRepositoryCommit"),
        f"{label}.request.targetRepositoryCommit",
        errors,
    )
    if report_commit != request_commit:
        errors.append(f"{label}.targetRepositoryCommit: request mismatch")
    _validate_workload_evaluation_context(
        report.get("evaluationContext"),
        report=report,
        result=result,
        evidence_git=evidence_git,
        root=root,
        trust=trust,
        label=f"{label}.evaluationContext",
        errors=errors,
    )
    evaluator_descriptor = report.get("evaluatorManifest")
    evaluator_document = _validate_workload_evaluator_manifest(
        evaluator_descriptor,
        request=request,
        code_git=code_git,
        evidence_git=evidence_git,
        root=root,
        mapping=mapping,
        trust=trust,
        label=f"{label}.evaluatorManifestReplayClosure",
        errors=errors,
    )
    role_descriptors: list[tuple[str, Mapping[str, Any]]] = []
    for role, candidate in (
        ("evaluationReport", descriptor),
        ("evaluationContext", report.get("evaluationContext")),
        ("evaluatorManifest", evaluator_descriptor),
        ("workloadDefinition", request.get("workloadDefinition")),
    ):
        if isinstance(candidate, Mapping):
            role_descriptors.append((role, candidate))
    entrypoint = definition.get("entrypoint")
    if isinstance(entrypoint, Mapping):
        for role in ("binary", "configuration"):
            candidate = entrypoint.get(role)
            if isinstance(candidate, Mapping):
                role_descriptors.append((f"workloadEntrypoint.{role}", candidate))
    if isinstance(evaluator_document, Mapping):
        for role in ("sourceTree", "buildAttestation"):
            candidate = evaluator_document.get(role)
            if isinstance(candidate, Mapping):
                role_descriptors.append((f"evaluator.{role}", candidate))
        evaluator_environment = evaluator_document.get("executionEnvironment")
        if isinstance(evaluator_environment, Mapping):
            for role in (
                "runtimeBinary",
                "dependencyLock",
                "environmentManifest",
                "buildLog",
            ):
                candidate = evaluator_environment.get(role)
                if isinstance(candidate, Mapping):
                    role_descriptors.append((f"evaluator.runtime.{role}", candidate))
    for number, observation in enumerate(report.get("artifactObservations", [])):
        if isinstance(observation, Mapping):
            role_descriptors.append((f"observation[{number}]", observation))
    for field in ("path", "sha256"):
        owners: dict[str, str] = {}
        for role, candidate in role_descriptors:
            value = candidate.get(field)
            if not isinstance(value, str):
                continue
            previous = owners.get(value)
            if previous is not None:
                errors.append(
                    f"{label}: {field} {value!r} reuses roles {previous} and {role}"
                )
            else:
                owners[value] = role
    for field in ("artifactObservations", "assertionResults", "metrics"):
        if report.get(field) != result.get(field):
            errors.append(f"{label}.{field}: WorkloadResult copy mismatch")
    report_outcome = report.get("evaluationOutcome")
    result_outcome = result.get("outcome")
    failure_reason = report.get("failureReasonCodeOrNull")
    terminal_reason = result.get("terminalReasonCodeOrNull")
    if result_outcome == "PASSED":
        if report_outcome != "PASSED" or failure_reason is not None:
            errors.append(f"{label}: PASSED result requires PASSED evaluation")
    elif report_outcome == "FAILED":
        if result_outcome != "FAILED" or terminal_reason is None:
            errors.append(f"{label}: FAILED evaluation/result mapping mismatch")
    elif report_outcome == "EVALUATION_ERROR":
        if result_outcome not in {"FAILED", "ABORTED"} or terminal_reason is None:
            errors.append(f"{label}: EVALUATION_ERROR result mapping mismatch")
    else:
        errors.append(f"{label}.evaluationOutcome: unknown terminal outcome")
    evaluated_at = _parse_time(report.get("evaluatedAt"), f"{label}.evaluatedAt", errors)
    wall = result.get("wallClockTiming")
    workload_finished = (
        _parse_time(
            wall.get("finishedAt"), f"{label}.result.finishedAt", errors
        )
        if isinstance(wall, Mapping)
        else None
    )
    result_created = _parse_time(
        result.get("createdAt"), f"{label}.result.createdAt", errors
    )
    signed_at = _parse_time(report.get("signedAt"), f"{label}.signedAt", errors)
    if (
        workload_finished is not None
        and evaluated_at is not None
        and evaluated_at < workload_finished
    ):
        errors.append(f"{label}.evaluatedAt: predates workload completion")
    if (
        evaluated_at is not None
        and signed_at is not None
        and evaluated_at >= signed_at
    ):
        errors.append(f"{label}.signedAt: must strictly follow evaluation")
    if (
        signed_at is not None
        and result_created is not None
        and signed_at >= result_created
    ):
        errors.append(f"{label}.signedAt: must precede WorkloadResult creation")
    for number, observation in enumerate(report.get("artifactObservations", [])):
        if not isinstance(observation, Mapping):
            continue
        observed_at = _parse_time(
            observation.get("observedAt"),
            f"{label}.artifactObservations[{number}].observedAt",
            errors,
        )
        if (
            observed_at is not None
            and evaluated_at is not None
            and observed_at > evaluated_at
        ):
            errors.append(
                f"{label}.artifactObservations[{number}]: postdates evaluation"
            )
    if isinstance(evaluator_document, Mapping):
        _replay_workload_evaluator(
            report=report,
            request_descriptor=request_descriptor,
            request=request,
            definition=definition,
            evaluator_manifest=evaluator_document,
            code_git=code_git,
            evidence_git=evidence_git,
            root=root,
            trust=trust,
            label=f"{label}.evaluatorReplay",
            errors=errors,
        )
    return report


def _validate_qualification_workload_result(
    descriptor: Any,
    *,
    request: Mapping[str, Any],
    definition: Mapping[str, Any],
    run: Mapping[str, Any],
    subject: Mapping[str, Any],
    code_git: _GitView | None,
    evidence_git: _GitView | None,
    root: Path,
    mapping: Mapping[str, Any] | None,
    trust: _TrustContext | None,
    label: str,
    errors: list[str],
) -> Mapping[str, Any] | None:
    schema_ref = "contracts/directpath-qualification-workload-result.schema.json"
    _blob, result = _resolve_pinned_json_descriptor(
        descriptor,
        expected_schema_ref=schema_ref,
        evidence_git=evidence_git,
        root=root,
        label=label,
        errors=errors,
    )
    if not isinstance(descriptor, Mapping) or not isinstance(result, Mapping):
        return None
    wall = result.get("wallClockTiming")
    finished_at = wall.get("finishedAt") if isinstance(wall, Mapping) else None
    _verify_history_signed_envelope(
        result,
        digest_field="resultDigest",
        signature_field="signature",
        signer_field="signerKeyId",
        signed_time_field="createdAt",
        domain="QMAN-DIRECTPATH/QUALIFICATION-WORKLOAD-RESULT/V1",
        required_role="TEST_EVIDENCE",
        trust=trust,
        evidence_git=evidence_git,
        root=root,
        label=label,
        errors=errors,
    )
    evaluation_report = _validate_workload_evaluation_report(
        result.get("evaluationReport"),
        result=result,
        request_descriptor=run.get("orchestratorRequest"),
        request=request,
        definition=definition,
        code_git=code_git,
        evidence_git=evidence_git,
        root=root,
        mapping=mapping,
        trust=trust,
        label=f"{label}.evaluationReport",
        errors=errors,
    )
    monotonic = result.get("monotonicTiming")
    descriptor_expected = {
        "workloadId": result.get("workloadId"),
        "workloadDefinitionDigest": result.get("workloadDefinitionDigest"),
        "outcome": result.get("outcome"),
        "startedAt": wall.get("startedAt") if isinstance(wall, Mapping) else None,
        "finishedAt": finished_at,
        "monotonicDurationNanoseconds": (
            monotonic.get("durationNanoseconds")
            if isinstance(monotonic, Mapping)
            else None
        ),
        "resultDigest": result.get("resultDigest"),
    }
    for field, expected in descriptor_expected.items():
        if descriptor.get(field) != expected:
            errors.append(f"{label}.{field}: parsed result mismatch")

    exact_result = {
        "qualificationRunId": request.get("qualificationRunId"),
        "qualificationRunRequestDigest": request.get("requestDigest"),
        "mappingCoreId": request.get("mappingCoreId"),
        "mappingCoreDigest": request.get("mappingCoreDigest"),
        "portableContractSha256": request.get("portableContractSha256"),
        "hostId": request.get("hostId"),
        "hostEpoch": request.get("hostEpoch"),
        "bootId": request.get("bootId"),
        "workloadId": definition.get("workloadId"),
        "workloadDefinitionDigest": definition.get("definitionDigest"),
    }
    for field, expected in exact_result.items():
        if result.get(field) != expected:
            errors.append(f"{label}.{field}: signed request/definition mismatch")
    result_commit = _normal_commit(
        result.get("targetRepositoryCommit"),
        f"{label}.targetRepositoryCommit",
        errors,
    )
    request_commit = _normal_commit(
        request.get("targetRepositoryCommit"),
        f"{label}.request.targetRepositoryCommit",
        errors,
    )
    if result_commit != request_commit:
        errors.append(f"{label}.targetRepositoryCommit: request mismatch")
    if result.get("outcome") != "PASSED" or result.get(
        "terminalReasonCodeOrNull"
    ) is not None:
        errors.append(f"{label}: QualificationSubject requires terminal PASSED")

    wall_started = (
        _parse_time(wall.get("startedAt"), f"{label}.wallClockTiming.startedAt", errors)
        if isinstance(wall, Mapping)
        else None
    )
    wall_finished = (
        _parse_time(finished_at, f"{label}.wallClockTiming.finishedAt", errors)
        if isinstance(wall, Mapping)
        else None
    )
    if wall_started is not None and wall_finished is not None:
        delta = wall_finished - wall_started
        duration_microseconds = (
            delta.days * 86_400_000_000
            + delta.seconds * 1_000_000
            + delta.microseconds
        )
        if duration_microseconds <= 0:
            errors.append(f"{label}.wallClockTiming: non-positive interval")
        elif wall.get("durationMicroseconds") != str(duration_microseconds):
            errors.append(f"{label}.wallClockTiming.durationMicroseconds: mismatch")
    run_started = _parse_time(run.get("startedAt"), f"{label}.run.startedAt", errors)
    run_finished = _parse_time(run.get("finishedAt"), f"{label}.run.finishedAt", errors)
    result_created = _parse_time(result.get("createdAt"), f"{label}.createdAt", errors)
    if (
        wall_finished is not None
        and result_created is not None
        and wall_finished >= result_created
    ):
        errors.append(f"{label}.createdAt: must follow workload completion")
    if (
        run_started is not None
        and wall_started is not None
        and wall_started < run_started
    ) or (
        run_finished is not None
        and wall_finished is not None
        and wall_finished > run_finished
    ):
        errors.append(f"{label}.wallClockTiming: outside QualificationRun interval")
    if (
        run_finished is not None
        and result_created is not None
        and result_created > run_finished
    ):
        errors.append(f"{label}.createdAt: follows QualificationRun completion")

    monotonic_duration: int | None = None
    if isinstance(monotonic, Mapping):
        try:
            monotonic_started = int(monotonic.get("startedNanoseconds"))
            monotonic_finished = int(monotonic.get("finishedNanoseconds"))
            monotonic_duration = int(monotonic.get("durationNanoseconds"))
        except (TypeError, ValueError):
            errors.append(f"{label}.monotonicTiming: invalid decimal nanoseconds")
        else:
            if (
                monotonic_finished <= monotonic_started
                or monotonic_duration != monotonic_finished - monotonic_started
            ):
                errors.append(f"{label}.monotonicTiming: inconsistent duration")
            minimum = definition.get("minimumDurationSeconds")
            if isinstance(minimum, int) and monotonic_duration < minimum * 1_000_000_000:
                errors.append(f"{label}.monotonicTiming: below definition minimum")
            run_monotonic = run.get("monotonicTiming")
            try:
                run_duration = int(run_monotonic.get("durationNanoseconds"))
            except (AttributeError, TypeError, ValueError):
                run_duration = None
            if run_duration is not None and monotonic_duration > run_duration:
                errors.append(f"{label}.monotonicTiming: exceeds run duration")

    artifacts = _require_canonical_object_order(
        result.get("artifactObservations"),
        ("artifactRole", "observationId", "sha256"),
        f"{label}.artifactObservations",
        errors,
    )
    artifact_by_hash: dict[str, Mapping[str, Any]] = {}
    artifact_documents: dict[str, Any] = {}
    artifact_projections: dict[str, Any] = {}
    for number, artifact in enumerate(artifacts):
        artifact_label = f"{label}.artifactObservations[{number}]"
        for field in ("observationId", "path", "sha256"):
            value = artifact.get(field)
            if any(existing.get(field) == value for existing in artifacts[:number]):
                errors.append(f"{artifact_label}.{field}: duplicate identity")
        digest = artifact.get("sha256")
        if isinstance(digest, str):
            artifact_by_hash[digest] = artifact
        artifact_blob = (
            evidence_git.blob(artifact.get("path"), f"{artifact_label}.path", errors)
            if evidence_git is not None
            else None
        )
        if evidence_git is None:
            errors.append(f"{artifact_label}: evidence repository E is unavailable")
        _check_blob_hash(artifact_blob, digest, artifact_label, errors)
        if artifact_blob is not None and artifact.get("byteLength") != len(artifact_blob):
            errors.append(f"{artifact_label}.byteLength: raw artifact mismatch")
        observed_at = _parse_time(
            artifact.get("observedAt"), f"{artifact_label}.observedAt", errors
        )
        if (
            wall_started is not None
            and observed_at is not None
            and observed_at < wall_started
        ) or (
            wall_finished is not None
            and observed_at is not None
            and observed_at > wall_finished
        ):
            errors.append(f"{artifact_label}.observedAt: outside workload interval")
        typed_tuple = (
            artifact.get("schemaRefOrNull"),
            artifact.get("schemaSha256OrNull"),
            artifact.get("valueProjectionOrNull"),
        )
        if any(value is None for value in typed_tuple) and not all(
            value is None for value in typed_tuple
        ):
            errors.append(f"{artifact_label}: typed projection tuple is partial")
        if all(isinstance(value, str) for value in typed_tuple):
            typed_ref, typed_digest, pointer = typed_tuple
            typed_schema = _worktree_bytes(
                root,
                typed_ref.split("#", 1)[0],
                f"{artifact_label}.schemaRef",
                errors,
            )
            _check_blob_hash(
                typed_schema, typed_digest, f"{artifact_label}.schema", errors
            )
            document = (
                _load_json_bytes(artifact_blob, artifact_label, errors)
                if artifact_blob is not None
                else None
            )
            if document is not None:
                _validate_closed_json_schema_instance(
                    document, root, typed_ref, artifact_label, errors
                )
                projected = _json_pointer_projection(
                    document, pointer, f"{artifact_label}.valueProjection", errors
                )
                if isinstance(digest, str):
                    artifact_documents[digest] = document
                    artifact_projections[digest] = projected
    required_roles = {
        role
        for role in (
            definition.get("requiredArtifactRoles", [])
            if isinstance(definition.get("requiredArtifactRoles"), list)
            else []
        )
        if isinstance(role, str)
    }
    observed_roles = {
        role
        for artifact in artifacts
        if isinstance((role := artifact.get("artifactRole")), str)
    }
    if observed_roles != required_roles:
        errors.append(
            f"{label}.artifactObservations: role vocabulary {sorted(observed_roles)!r} "
            f"does not equal definition {sorted(required_roles)!r}"
        )

    definition_assertion_rows = [
        item
        for item in definition.get("mandatoryAssertions", [])
        if isinstance(item, Mapping) and isinstance(item.get("assertionId"), str)
    ]
    definition_assertions = {
        item.get("assertionId"): item
        for item in definition_assertion_rows
    }
    assertion_results = _require_canonical_object_order(
        result.get("assertionResults"),
        ("assertionId",),
        f"{label}.assertionResults",
        errors,
    )
    result_assertion_ids = [
        item.get("assertionId")
        for item in assertion_results
        if isinstance(item.get("assertionId"), str)
    ]
    report_outcome = (
        evaluation_report.get("evaluationOutcome")
        if isinstance(evaluation_report, Mapping)
        else None
    )
    expected_assertion_ids = [
        item.get("assertionId") for item in definition_assertion_rows
    ]
    if report_outcome == "EVALUATION_ERROR":
        if result_assertion_ids != expected_assertion_ids[: len(result_assertion_ids)]:
            errors.append(
                f"{label}.assertionResults: EVALUATION_ERROR permits only the "
                "canonical completed prefix"
            )
    elif result_assertion_ids != expected_assertion_ids:
        errors.append(f"{label}.assertionResults: definition bijection mismatch")
    for number, assertion_result in enumerate(assertion_results):
        assertion_label = f"{label}.assertionResults[{number}]"
        definition_assertion = definition_assertions.get(
            assertion_result.get("assertionId")
        )
        if not isinstance(definition_assertion, Mapping):
            continue
        oracle = definition_assertion.get("oracle")
        expected = {
            "assertionDigest": definition_assertion.get("assertionDigest"),
            "oracleId": oracle.get("oracleId") if isinstance(oracle, Mapping) else None,
            "evaluatorId": (
                oracle.get("evaluatorId") if isinstance(oracle, Mapping) else None
            ),
            "evaluatorDefinitionDigest": (
                oracle.get("evaluatorDefinitionDigest")
                if isinstance(oracle, Mapping)
                else None
            ),
        }
        for field, value in expected.items():
            if assertion_result.get(field) != value:
                errors.append(f"{assertion_label}.{field}: definition mismatch")
        if result.get("outcome") == "PASSED" and assertion_result.get("verdict") != "PASS":
            errors.append(f"{assertion_label}.verdict: PASSED result requires PASS")
        evidence_hashes = assertion_result.get("evidenceArtifactSha256s")
        _require_canonical_set_order(
            evidence_hashes, f"{assertion_label}.evidenceArtifactSha256s", errors
        )
        evidence_artifacts = [
            artifact_by_hash.get(digest)
            for digest in (evidence_hashes if isinstance(evidence_hashes, list) else [])
        ]
        if any(not isinstance(artifact, Mapping) for artifact in evidence_artifacts):
            errors.append(f"{assertion_label}: evidence hash does not resolve")
        evidence_roles = {
            role
            for artifact in evidence_artifacts
            if isinstance(artifact, Mapping)
            and isinstance((role := artifact.get("artifactRole")), str)
        }
        required_assertion_roles = {
            role
            for role in (
                definition_assertion.get("requiredEvidenceRoles", [])
                if isinstance(
                    definition_assertion.get("requiredEvidenceRoles"), list
                )
                else []
            )
            if isinstance(role, str)
        }
        if evidence_roles != required_assertion_roles:
            errors.append(f"{assertion_label}: evidence role coverage mismatch")

    definition_metric_rows = [
        item
        for item in definition.get("metricDefinitions", [])
        if isinstance(item, Mapping) and isinstance(item.get("metricId"), str)
    ]
    definition_metrics = {
        item.get("metricId"): item
        for item in definition_metric_rows
    }
    metrics = _require_canonical_object_order(
        result.get("metrics"),
        ("metricId", "aggregation", "unit"),
        f"{label}.metrics",
        errors,
    )
    metric_ids = [
        metric.get("metricId")
        for metric in metrics
        if isinstance(metric.get("metricId"), str)
    ]
    expected_metric_ids = [item.get("metricId") for item in definition_metric_rows]
    if report_outcome == "EVALUATION_ERROR":
        if metric_ids != expected_metric_ids[: len(metric_ids)]:
            errors.append(
                f"{label}.metrics: EVALUATION_ERROR permits only the canonical "
                "completed prefix"
            )
    elif metric_ids != expected_metric_ids:
        errors.append(f"{label}.metrics: definition bijection mismatch")
    for number, metric in enumerate(metrics):
        metric_label = f"{label}.metrics[{number}]"
        definition_metric = definition_metrics.get(metric.get("metricId"))
        if not isinstance(definition_metric, Mapping):
            continue
        for field in (
            "metricDefinitionDigest",
            "evaluatorId",
            "evaluatorDefinitionDigest",
            "aggregation",
            "outputScale",
            "unit",
        ):
            if metric.get(field) != definition_metric.get(field):
                errors.append(f"{metric_label}.{field}: definition mismatch")
        source_hashes = metric.get("sourceArtifactSha256s")
        _require_canonical_set_order(
            source_hashes, f"{metric_label}.sourceArtifactSha256s", errors
        )
        sources = [
            artifact_by_hash.get(digest)
            for digest in (source_hashes if isinstance(source_hashes, list) else [])
        ]
        if any(not isinstance(source, Mapping) for source in sources):
            errors.append(f"{metric_label}: source artifact hash does not resolve")
        allowed_roles = {
            role
            for role in (
                definition_metric.get("sourceRoleAllowlist", [])
                if isinstance(definition_metric.get("sourceRoleAllowlist"), list)
                else []
            )
            if isinstance(role, str)
        }
        if any(
            source.get("artifactRole") not in allowed_roles
            for source in sources
            if isinstance(source, Mapping)
        ):
            errors.append(f"{metric_label}: source role is outside definition")
        exact_projection = definition_metric.get("exactValueProjection")
        samples: list[Fraction] = []
        if isinstance(exact_projection, Mapping):
            for digest, source in zip(
                source_hashes if isinstance(source_hashes, list) else [], sources
            ):
                if not isinstance(source, Mapping):
                    continue
                typed_expected = (
                    exact_projection.get("sourceSchemaRef"),
                    exact_projection.get("sourceSchemaSha256"),
                    exact_projection.get("jsonPointer"),
                )
                typed_actual = (
                    source.get("schemaRefOrNull"),
                    source.get("schemaSha256OrNull"),
                    source.get("valueProjectionOrNull"),
                )
                if typed_actual != typed_expected:
                    errors.append(f"{metric_label}: source typed projection mismatch")
                samples.extend(
                    _decimal_samples(
                        artifact_projections.get(digest),
                        f"{metric_label}.source[{digest}]",
                        errors,
                    )
                )
        sample_count = metric.get("sampleCount")
        if sample_count != len(samples):
            errors.append(f"{metric_label}.sampleCount: projected sample mismatch")
        value_contract = definition_metric.get("valueContract")
        lower: Fraction | None = None
        upper: Fraction | None = None
        if isinstance(value_contract, Mapping):
            minimum_count = value_contract.get("minimumSampleCount")
            maximum_count = value_contract.get("maximumSampleCount")
            if isinstance(sample_count, int) and isinstance(minimum_count, int) and (
                sample_count < minimum_count
            ):
                errors.append(f"{metric_label}.sampleCount: below definition minimum")
            if isinstance(sample_count, int) and isinstance(maximum_count, int) and (
                sample_count > maximum_count
            ):
                errors.append(f"{metric_label}.sampleCount: above definition maximum")
            lower = (
                _decimal_fraction(
                    value_contract.get("minimumInclusiveOrNull"),
                    f"{metric_label}.minimumInclusiveOrNull",
                    errors,
                )
                if value_contract.get("minimumInclusiveOrNull") is not None
                else None
            )
            upper = (
                _decimal_fraction(
                    value_contract.get("maximumInclusiveOrNull"),
                    f"{metric_label}.maximumInclusiveOrNull",
                    errors,
                )
                if value_contract.get("maximumInclusiveOrNull") is not None
                else None
            )
            for sample_number, sample in enumerate(samples):
                if lower is not None and sample < lower:
                    errors.append(
                        f"{metric_label}.samples[{sample_number}]: "
                        "below inclusive bound"
                    )
                if upper is not None and sample > upper:
                    errors.append(
                        f"{metric_label}.samples[{sample_number}]: "
                        "above inclusive bound"
                    )
        window_started = _parse_time(
            metric.get("windowStartedAt"), f"{metric_label}.windowStartedAt", errors
        )
        window_finished = _parse_time(
            metric.get("windowFinishedAt"), f"{metric_label}.windowFinishedAt", errors
        )
        if (
            window_started is not None
            and window_finished is not None
            and window_started > window_finished
        ) or (
            wall_started is not None
            and window_started is not None
            and window_started < wall_started
        ) or (
            wall_finished is not None
            and window_finished is not None
            and window_finished > wall_finished
        ):
            errors.append(f"{metric_label}: metric window is outside workload interval")
        result_monotonic = result.get("monotonicTiming")
        try:
            window_started_ns = int(metric.get("windowStartedNanoseconds"))
            window_finished_ns = int(metric.get("windowFinishedNanoseconds"))
            result_started_ns = int(result_monotonic.get("startedNanoseconds"))
            result_finished_ns = int(result_monotonic.get("finishedNanoseconds"))
        except (AttributeError, TypeError, ValueError):
            errors.append(f"{metric_label}: invalid monotonic metric window")
            window_duration_ns = None
        else:
            window_duration_ns = window_finished_ns - window_started_ns
            if (
                window_duration_ns <= 0
                or window_started_ns < result_started_ns
                or window_finished_ns > result_finished_ns
            ):
                errors.append(
                    f"{metric_label}: monotonic window is outside workload interval"
                )
            if metric.get("monotonicClockId") != result_monotonic.get("clockId"):
                errors.append(f"{metric_label}.monotonicClockId: workload mismatch")
        expected_value = _aggregate_metric_samples(
            samples,
            metric.get("aggregation"),
            metric.get("outputScale"),
            window_duration_ns,
            metric_label,
            errors,
        )
        if metric.get("valueDecimal") != expected_value:
            errors.append(
                f"{metric_label}.valueDecimal: evaluator aggregation mismatch"
            )

    observation = subject.get("workloadObservation")
    if isinstance(observation, Mapping):
        if observation.get("startedAt") != descriptor.get("startedAt"):
            errors.append(f"{label}: Subject workload start mismatch")
        if observation.get("finishedAt") != descriptor.get("finishedAt"):
            errors.append(f"{label}: Subject workload finish mismatch")
        if observation.get("workloadResultArtifactSha256") != descriptor.get("sha256"):
            errors.append(f"{label}: Subject workload-result raw hash mismatch")
        if observation.get("monotonicDurationNanoseconds") != descriptor.get(
            "monotonicDurationNanoseconds"
        ):
            errors.append(f"{label}: Subject workload monotonic duration mismatch")
    del evaluation_report
    return result


QUALIFICATION_RUN_DESCRIPTOR_FIELDS = {
    "path",
    "sha256",
    "byteLength",
    "mediaType",
    "schemaRef",
    "schemaSha256",
    "runDigest",
}


def _derive_qualification_pci_identity(
    device: Mapping[str, Any],
    errata_profile_id: Any,
    *,
    label: str,
    errors: list[str],
) -> Mapping[str, Any] | None:
    """Derive the exact qualification identity from one DeviceRecord."""

    immutable = device.get("immutableIdentity")
    if not isinstance(immutable, Mapping):
        errors.append(f"{label}.immutableIdentity: expected object")
        return None
    pci_ids = immutable.get("pciIds")
    if not isinstance(pci_ids, Mapping):
        errors.append(f"{label}.immutableIdentity.pciIds: expected object")
        return None
    try:
        identity_bytes = canonical_json_bytes(immutable)
    except (CanonicalizationError, TypeError, ValueError) as exc:
        errors.append(f"{label}.immutableIdentity: cannot canonicalize: {exc}")
        return None
    identity_fingerprint = sha256(identity_bytes)
    if device.get("identityFingerprint") != identity_fingerprint:
        errors.append(f"{label}.identityFingerprint: immutable identity mismatch")
    host_stable_id = immutable.get("hostStableId")
    expected_uid = (
        f"urn:qman:directpath:device:v1:{host_stable_id}:{identity_fingerprint}"
        if isinstance(host_stable_id, str)
        else None
    )
    if device.get("deviceUid") != expected_uid:
        errors.append(f"{label}.deviceUid: immutable identity mismatch")
    if device.get("hostId") != host_stable_id:
        errors.append(f"{label}.hostId: immutable identity mismatch")
    role = device.get("role")
    if not isinstance(role, Mapping) or role.get("functionRole") != pci_ids.get(
        "functionRole"
    ):
        errors.append(f"{label}.role.functionRole: immutable identity mismatch")

    device_projection = copy.deepcopy(dict(device))
    device_projection["deviceRecordHash"] = None
    expected_record_hash = _canonical_digest(
        device_projection, f"{label}.deviceRecordHash projection", errors
    )
    if device.get("deviceRecordHash") != expected_record_hash:
        errors.append(f"{label}.deviceRecordHash: canonical projection mismatch")
    _require_canonical_set_order(
        device.get("technicalTraits"), f"{label}.technicalTraits", errors
    )

    identity_variant = immutable.get("identityVariant")
    provider: Mapping[str, Any] | None = None
    serial_value_hash: Any = None
    physical_path: Any = None
    vendor_extractor_id: Any = None
    vendor_extractor_digest: Any = None
    if identity_variant == "STRONG_SERIAL":
        candidate_provider = immutable.get("serialProvider")
        serial_material = immutable.get("serialMaterial")
        if isinstance(candidate_provider, Mapping):
            provider = candidate_provider
        else:
            errors.append(f"{label}.immutableIdentity.serialProvider: expected object")
        if not isinstance(serial_material, Mapping):
            errors.append(f"{label}.immutableIdentity.serialMaterial: expected object")
        serial_value_hash = immutable.get("serialValueHash")
        if isinstance(provider, Mapping) and isinstance(serial_material, Mapping):
            canonical_hex = serial_material.get("canonicalSerialBytesHex")
            try:
                canonical_serial = bytes.fromhex(canonical_hex)
            except (TypeError, ValueError):
                errors.append(
                    f"{label}.immutableIdentity.serialMaterial."
                    "canonicalSerialBytesHex: invalid bytes"
                )
            else:
                expected_serial_hash = sha256(
                    b"QMAN-DIRECTPATH/SERIAL-VALUE/V1\x00"
                    + str(provider.get("providerId")).encode("ascii")
                    + b"\x00"
                    + canonical_serial
                )
                if serial_value_hash != expected_serial_hash:
                    errors.append(
                        f"{label}.immutableIdentity.serialValueHash: projection mismatch"
                    )
            if provider.get("providerId") == "VENDOR_QUALIFIED_BYTES_V1":
                vendor_extractor_id = serial_material.get("vendorExtractorId")
                vendor_extractor_digest = serial_material.get(
                    "vendorExtractorDefinitionDigest"
                )
    elif identity_variant == "SLOT_BOUND":
        candidate_provider = immutable.get("physicalPathProvider")
        if isinstance(candidate_provider, Mapping):
            provider = candidate_provider
        else:
            errors.append(
                f"{label}.immutableIdentity.physicalPathProvider: expected object"
            )
        physical_path = immutable.get("physicalPath")
        if device.get("physicalPathProvider") != candidate_provider or device.get(
            "physicalPath"
        ) != physical_path:
            errors.append(f"{label}.physicalPath: slot-bound identity mismatch")
    else:
        errors.append(f"{label}.immutableIdentity.identityVariant: unknown variant")
    if not isinstance(provider, Mapping):
        return None
    if errata_profile_id != "NONE":
        errors.append(
            f"{label}.errataProfileId: portable revision requires fixed NONE"
        )

    result = {
        field: copy.deepcopy(pci_ids.get(field))
        for field in (
            "vendorId",
            "deviceId",
            "subsystemVendorId",
            "subsystemDeviceId",
            "revisionId",
            "classCode",
            "functionRoleAlgorithm",
            "functionRoleAlgorithmVersion",
            "functionRoleDefinitionDigest",
            "functionRole",
        )
    }
    result.update(
        {
            "identityVariant": identity_variant,
            "identityProviderId": provider.get("providerId"),
            "identityProviderVersion": provider.get("providerVersion"),
            "identityProviderDefinitionDigest": provider.get(
                "providerDefinitionDigest"
            ),
            "identityVectorSetDigest": (
                "sha256:0d24bf773afc921caa8965b69588cbfb5876e6c636c283b3"
                "ff3362507b9ee693"
            ),
            "serialValueHashOrNull": serial_value_hash,
            "physicalPathOrNull": physical_path,
            "vendorExtractorIdOrNull": vendor_extractor_id,
            "vendorExtractorDefinitionDigestOrNull": vendor_extractor_digest,
            "errataProfileId": "NONE",
        }
    )
    return result


def _validate_device_taxonomy_definition(
    descriptor: Any,
    *,
    classification: Mapping[str, Any],
    run: Mapping[str, Any],
    code_git: _GitView | None,
    evidence_git: _GitView | None,
    root: Path,
    mapping: Mapping[str, Any] | None,
    trust: _TrustContext | None,
    label: str,
    errors: list[str],
) -> tuple[Mapping[str, Any] | None, list[dict[str, Any]], str | None]:
    """Validate the signed taxonomy plus classifier source/build/runtime closure."""

    schema_ref = "contracts/directpath-device-taxonomy-definition.schema.json"
    _blob, taxonomy = _resolve_pinned_json_descriptor(
        descriptor,
        expected_schema_ref=schema_ref,
        evidence_git=evidence_git,
        root=root,
        label=label,
        errors=errors,
    )
    if not isinstance(descriptor, Mapping) or not isinstance(taxonomy, Mapping):
        return None, [], None
    _verify_history_signed_envelope(
        taxonomy,
        digest_field="definitionDigest",
        signature_field="signature",
        signer_field="signerKeyId",
        signed_time_field="issuedAt",
        domain="QMAN-DIRECTPATH/DEVICE-TAXONOMY-DEFINITION/V1",
        required_role="QUALIFICATION_ENGINEERING",
        trust=trust,
        evidence_git=evidence_git,
        root=root,
        label=label,
        errors=errors,
    )
    for field in ("taxonomyId", "definitionDigest"):
        if descriptor.get(field) != taxonomy.get(field):
            errors.append(f"{label}.{field}: parsed taxonomy mismatch")
    exact_identity = {
        "targetRepositoryCommit": run.get("targetRepositoryCommit"),
        "mappingCoreId": run.get("mappingCoreId"),
        "portableContractSha256": run.get("portableContractSha256"),
    }
    for field, expected in exact_identity.items():
        if field == "targetRepositoryCommit":
            actual = _normal_commit(taxonomy.get(field), f"{label}.{field}", errors)
            expected_value = _normal_commit(
                expected, f"{label}.run.{field}", errors
            )
        else:
            actual = taxonomy.get(field)
            expected_value = expected
        if actual != expected_value or taxonomy.get(field) != classification.get(field):
            errors.append(f"{label}.{field}: classification/run mismatch")

    archetypes = taxonomy.get("archetypes")
    if not isinstance(archetypes, list):
        errors.append(f"{label}.archetypes: expected array")
        archetypes = []
    precedences = [
        item.get("precedence") for item in archetypes if isinstance(item, Mapping)
    ]
    archetype_ids = [
        item.get("archetype") for item in archetypes if isinstance(item, Mapping)
    ]
    profiles = [
        item.get("qualificationCaseProfileId")
        for item in archetypes
        if isinstance(item, Mapping)
    ]
    if (
        len(archetypes) != 5
        or precedences != [1, 2, 3, 4, 5]
        or len(set(archetype_ids)) != 5
        or len(set(profiles)) != 5
        or archetype_ids[-1:] != ["GENERIC_PCI"]
    ):
        errors.append(
            f"{label}.archetypes: expected five unique precedence rows with "
            "GENERIC_PCI final"
        )

    classifier = taxonomy.get("classifier")
    if not isinstance(classifier, Mapping):
        errors.append(f"{label}.classifier: expected object")
        return taxonomy, [], None
    classifier_blob = (
        code_git.blob(classifier.get("path"), f"{label}.classifier.path", errors)
        if code_git is not None
        else None
    )
    if code_git is None:
        errors.append(f"{label}.classifier: target repository C is unavailable")
    _check_blob_hash(
        classifier_blob, classifier.get("blobSha256"), f"{label}.classifier", errors
    )
    binding_matches: list[Mapping[str, Any]] = []
    if isinstance(mapping, Mapping):
        binding_matches = [
            binding
            for item in mapping.get("mappings", [])
            if isinstance(item, Mapping)
            for binding in item.get("targetBindings", [])
            if isinstance(binding, Mapping)
            and binding.get("path") == classifier.get("path")
            and binding.get("symbol") == classifier.get("symbol")
            and binding.get("hashScope") == "GIT_BLOB_BYTES"
            and binding.get("interfaceHash") == classifier.get("blobSha256")
            and binding.get("symbolSemanticHash")
            == classifier.get("symbolSemanticHash")
            and binding.get("symbolKind") in {"FUNCTION", "TEST"}
        ]
    if len(binding_matches) != 1:
        errors.append(
            f"{label}.classifier: path/symbol/blob/semantic tuple resolves "
            f"{len(binding_matches)} target bindings"
        )

    source_tree = taxonomy.get("sourceTree")
    tracked_paths: set[str] = set()
    if isinstance(source_tree, Mapping):
        _validate_source_tree_manifest(
            {
                "sourceTreeManifestPath": source_tree.get("path"),
                "sourceTreeManifestSha256": source_tree.get("sha256"),
                "sourceTreeManifestSchemaSha256": source_tree.get("schemaSha256"),
                "sourceTreeSha256": source_tree.get("sourceTreeSha256"),
            },
            code_git,
            evidence_git,
            root,
            f"{label}.sourceTree",
            errors,
            _tracked_paths=tracked_paths,
        )
        if classifier.get("path") not in tracked_paths:
            errors.append(f"{label}.sourceTree: classifier path is absent")
    else:
        errors.append(f"{label}.sourceTree: expected descriptor")

    build_bundle = _validate_build_attestation(
        taxonomy.get("buildAttestation"),
        expected_consumer_kind="TAXONOMY_CLASSIFIER",
        expected_consumer_build_id=classifier.get("manifestId"),
        expected_target_commit=taxonomy.get("targetRepositoryCommit"),
        expected_mapping_core_id=taxonomy.get("mappingCoreId"),
        expected_portable_contract_sha256=taxonomy.get("portableContractSha256"),
        expected_source_tree=(
            dict(source_tree) if isinstance(source_tree, Mapping) else None
        ),
        code_git=code_git,
        evidence_git=evidence_git,
        root=root,
        trust=trust,
        label=f"{label}.buildAttestation",
        errors=errors,
    )
    build_attestation = (
        build_bundle.get("attestation")
        if isinstance(build_bundle, Mapping)
        and isinstance(build_bundle.get("attestation"), Mapping)
        else None
    )
    build_artifacts = (
        build_bundle.get("artifacts")
        if isinstance(build_bundle, Mapping)
        and isinstance(build_bundle.get("artifacts"), Mapping)
        else None
    )
    taxonomy_issued = _parse_time(taxonomy.get("issuedAt"), f"{label}.issuedAt", errors)
    if isinstance(build_attestation, Mapping):
        attested = _parse_time(
            build_attestation.get("attestedAt"),
            f"{label}.buildAttestation.attestedAt",
            errors,
        )
        if attested is not None and taxonomy_issued is not None and attested >= taxonomy_issued:
            errors.append(f"{label}.issuedAt: must follow BuildAttestation")

    environment = taxonomy.get("executionEnvironment")
    if (
        isinstance(environment, Mapping)
        and isinstance(build_attestation, Mapping)
        and isinstance(build_artifacts, Mapping)
    ):
        for role in ("runtimeBinary", "dependencyLock", "environmentManifest", "buildLog"):
            artifact = environment.get(role)
            if isinstance(artifact, Mapping) and evidence_git is not None:
                artifact_blob = evidence_git.blob(
                    artifact.get("path"), f"{label}.executionEnvironment.{role}.path", errors
                )
                _check_blob_hash(
                    artifact_blob,
                    artifact.get("sha256"),
                    f"{label}.executionEnvironment.{role}",
                    errors,
                )
                if artifact_blob is not None and artifact.get("byteLength") != len(artifact_blob):
                    errors.append(f"{label}.executionEnvironment.{role}.byteLength: mismatch")
        output = build_attestation.get("output")
        mode = build_attestation.get("mode")
        runtime_binary = environment.get("runtimeBinary")
        if mode == "INTERPRETED_NO_BUILD":
            if environment.get("mode") != "INTERPRETED":
                errors.append(f"{label}.executionEnvironment.mode: expected INTERPRETED")
            if (
                not isinstance(output, Mapping)
                or output.get("kind") != "INTERPRETED_RUNTIME"
                or output.get("role") != "TAXONOMY_CLASSIFIER_SOURCE"
            ):
                errors.append(f"{label}.buildAttestation.output: classifier role mismatch")
            elif isinstance(output.get("entrypointSource"), Mapping) and (
                output["entrypointSource"].get("path") != classifier.get("path")
                or output["entrypointSource"].get("contentSha256")
                != classifier.get("blobSha256")
            ):
                errors.append(f"{label}.buildAttestation.output: classifier source mismatch")
            toolchain = build_attestation.get("toolchain")
            interpreter_id = output.get("interpreterComponentId") if isinstance(output, Mapping) else None
            interpreter_artifacts = [
                item.get("artifact")
                for item in (
                    toolchain.get("components", [])
                    if isinstance(toolchain, Mapping)
                    else []
                )
                if isinstance(item, Mapping)
                and item.get("componentId") == interpreter_id
                and item.get("role") == "INTERPRETER"
            ]
            if len(interpreter_artifacts) != 1 or runtime_binary != interpreter_artifacts[0]:
                errors.append(f"{label}.executionEnvironment.runtimeBinary: interpreter mismatch")
        else:
            if environment.get("mode") == "INTERPRETED":
                errors.append(f"{label}.executionEnvironment.mode: produced classifier mismatch")
            if (
                not isinstance(output, Mapping)
                or output.get("kind") != "PRODUCED_ARTIFACT"
                or output.get("role") != "TAXONOMY_CLASSIFIER_BINARY"
                or output.get("executable") is not True
                or output.get("consumerRuntimeMode") != environment.get("mode")
                or output.get("artifact") != runtime_binary
            ):
                errors.append(f"{label}.buildAttestation.output: produced classifier mismatch")
        exact_environment = {
            "dependencyLock": build_artifacts.get("dependencies.lockArtifact"),
            "environmentManifest": build_artifacts.get("environment.manifest"),
            "buildLog": build_artifacts.get("buildLog"),
        }
        for role, expected in exact_environment.items():
            if environment.get(role) != expected:
                errors.append(f"{label}.executionEnvironment.{role}: build mismatch")
    else:
        errors.append(f"{label}.executionEnvironment: complete build projection unavailable")

    input_contracts = taxonomy.get("inputContracts")
    schema_contracts: list[tuple[str, Mapping[str, Any]]] = []
    expected_input_refs = {
        "hostSnapshot": "contracts/directpath-portable-hash-subjects.schema.json#/$defs/hostSnapshot",
        "deviceRecord": "contracts/directpath-portable-entities.schema.json#/$defs/ENTITY-DEVICE-RECORD",
        "classificationContext": "contracts/directpath-device-classification-record.schema.json#/$defs/classificationContext",
    }
    if isinstance(input_contracts, Mapping):
        for role, expected_ref in expected_input_refs.items():
            item = input_contracts.get(role)
            if not isinstance(item, Mapping):
                errors.append(f"{label}.inputContracts.{role}: expected schema contract")
                continue
            schema_contracts.append((role, item))
            if item.get("schemaRef") != expected_ref:
                errors.append(f"{label}.inputContracts.{role}.schemaRef: mismatch")
    output_contract = taxonomy.get("outputContract")
    if isinstance(output_contract, Mapping):
        schema_contracts.append(("outputContract", output_contract))
        if output_contract.get("schemaRef") != (
            "contracts/directpath-device-classification-record.schema.json"
        ):
            errors.append(f"{label}.outputContract.schemaRef: mismatch")
    else:
        errors.append(f"{label}.outputContract: expected schema contract")
    for role, item in schema_contracts:
        schema_path = str(item.get("schemaRef", "")).split("#", 1)[0]
        schema_blob = _worktree_bytes(root, schema_path, f"{label}.{role}.schemaRef", errors)
        _check_blob_hash(schema_blob, item.get("schemaSha256"), f"{label}.{role}.schema", errors)
    interface_projection = {
        "protocol": classifier.get("protocol"),
        "argvOrder": [
            "taxonomy",
            "hostSnapshot",
            "deviceRecord",
            "classificationContext",
            "output",
        ],
        "environment": {"LC_ALL": "C.UTF-8", "TZ": "UTC"},
        "network": "DENY_ALL",
        "inputContracts": copy.deepcopy(taxonomy.get("inputContracts")),
        "outputContract": copy.deepcopy(taxonomy.get("outputContract")),
    }
    interface_digest = _canonical_digest(
        interface_projection,
        f"{label}.classifier.interfaceContractDigest projection",
        errors,
    )
    if classifier.get("interfaceContractDigest") != interface_digest:
        errors.append(f"{label}.classifier.interfaceContractDigest: projection mismatch")

    closure, architecture = _collect_consumer_replay_closure(
        consumer_kind="TAXONOMY_CLASSIFIER",
        manifest_descriptor=descriptor,
        manifest=taxonomy,
        consumer_build_id=classifier.get("manifestId"),
        code_git=code_git,
        evidence_git=evidence_git,
        root=root,
        trust=trust,
        label=f"{label}.replayClosure",
        errors=errors,
    )
    return taxonomy, closure, architecture


def _validate_device_classification_record(
    binding: Mapping[str, Any],
    *,
    expected_device_descriptor: Mapping[str, Any] | None,
    measured_archetype: Any,
    measurement_observed_at: Any,
    run: Mapping[str, Any],
    subject: Mapping[str, Any],
    record: Mapping[str, Any],
    code_git: _GitView | None,
    evidence_git: _GitView | None,
    root: Path,
    mapping: Mapping[str, Any] | None,
    trust: _TrustContext | None,
    label: str,
    errors: list[str],
) -> None:
    """Validate and replay the sole deviceArchetype classification authority."""

    schema_ref = "contracts/directpath-device-classification-record.schema.json"
    descriptor = {
        "path": binding.get("path"),
        "sha256": binding.get("sha256"),
        "byteLength": binding.get("byteLength"),
        "mediaType": binding.get("mediaType"),
        "schemaRef": binding.get("schemaRefOrNull"),
        "schemaSha256": binding.get("schemaSha256OrNull"),
    }
    _classification_blob, classification = _resolve_pinned_json_descriptor(
        descriptor,
        expected_schema_ref=schema_ref,
        evidence_git=evidence_git,
        root=root,
        label=label,
        errors=errors,
    )
    if not isinstance(classification, Mapping):
        return
    final_key = _verify_history_signed_envelope(
        classification,
        digest_field="classificationDigest",
        signature_field="signature",
        signer_field="signerKeyId",
        signed_time_field="signedAt",
        domain="QMAN-DIRECTPATH/DEVICE-CLASSIFICATION-RECORD/V1",
        required_role="QUALIFICATION_ENGINEERING",
        trust=trust,
        evidence_git=evidence_git,
        root=root,
        label=label,
        errors=errors,
    )
    if classification.get("deviceArchetype") != measured_archetype:
        errors.append(f"{label}.deviceArchetype: QualificationMeasurement mismatch")
    for field in ("targetRepositoryCommit", "mappingCoreId", "portableContractSha256"):
        if field == "targetRepositoryCommit":
            actual = _normal_commit(classification.get(field), f"{label}.{field}", errors)
            expected = _normal_commit(run.get(field), f"{label}.run.{field}", errors)
        else:
            actual = classification.get(field)
            expected = run.get(field)
        if actual != expected:
            errors.append(f"{label}.{field}: QualificationRun mismatch")
    if classification.get("hostId") != run.get("hostId") or classification.get(
        "hostEpoch"
    ) != run.get("hostEpoch") or classification.get("bootId") != run.get("bootId"):
        errors.append(f"{label}: host/epoch/boot tuple does not equal QualificationRun")

    taxonomy_descriptor = classification.get("taxonomyDefinition")
    taxonomy, closure, architecture = _validate_device_taxonomy_definition(
        taxonomy_descriptor,
        classification=classification,
        run=run,
        code_git=code_git,
        evidence_git=evidence_git,
        root=root,
        mapping=mapping,
        trust=trust,
        label=f"{label}.taxonomyDefinition",
        errors=errors,
    )
    if not isinstance(taxonomy, Mapping):
        return

    inventory_descriptor = classification.get("inventorySnapshot")
    inventory_blob, inventory = _resolve_pinned_json_descriptor(
        inventory_descriptor,
        expected_schema_ref=(
            "contracts/directpath-portable-hash-subjects.schema.json#/$defs/hostSnapshot"
        ),
        evidence_git=evidence_git,
        root=root,
        label=f"{label}.inventorySnapshot",
        errors=errors,
    )
    if isinstance(inventory, Mapping):
        _verify_history_signed_envelope(
            inventory,
            digest_field="contentHash",
            signature_field="signature",
            signer_field="signerKeyId",
            signed_time_field="capturedAt",
            domain="QMAN-DIRECTPATH/HOST-SNAPSHOT/V1",
            required_role="HOST_INVENTORY_EVIDENCE",
            trust=trust,
            evidence_git=evidence_git,
            root=root,
            label=f"{label}.inventorySnapshot",
            errors=errors,
        )
        if isinstance(inventory_descriptor, Mapping) and inventory_descriptor.get(
            "contentHash"
        ) != inventory.get("contentHash"):
            errors.append(f"{label}.inventorySnapshot.contentHash: parsed mismatch")
    current_snapshot = run.get("currentInventorySnapshot")
    if isinstance(current_snapshot, Mapping) and isinstance(inventory_descriptor, Mapping):
        expected_inventory_descriptor = {
            "path": current_snapshot.get("path"),
            "sha256": current_snapshot.get("sha256"),
            "byteLength": current_snapshot.get("byteLength"),
            "mediaType": current_snapshot.get("mediaType"),
            "schemaRef": current_snapshot.get("schemaRef"),
            "schemaSha256": current_snapshot.get("schemaSha256"),
            "contentHash": current_snapshot.get("inventorySnapshotDigest"),
        }
        if inventory_descriptor != expected_inventory_descriptor:
            errors.append(
                f"{label}.inventorySnapshot: must equal current QualificationRun snapshot descriptor"
            )
    else:
        errors.append(f"{label}.inventorySnapshot: current run pointer is unavailable")

    device_descriptor = classification.get("deviceRecord")
    if (
        expected_device_descriptor is None
        or device_descriptor != expected_device_descriptor
    ):
        errors.append(
            f"{label}.deviceRecord: identity/traits/classification must bind "
            "the same exact DeviceRecord descriptor"
        )
    device_blob, device = _resolve_pinned_json_descriptor(
        device_descriptor,
        expected_schema_ref=(
            "contracts/directpath-portable-entities.schema.json#/$defs/ENTITY-DEVICE-RECORD"
        ),
        evidence_git=evidence_git,
        root=root,
        label=f"{label}.deviceRecord",
        errors=errors,
    )
    if isinstance(device, Mapping):
        subject_identity = subject.get("pciIdentityMatch")
        errata_profile_id = (
            subject_identity.get("errataProfileId")
            if isinstance(subject_identity, Mapping)
            else None
        )
        derived_identity = _derive_qualification_pci_identity(
            device,
            errata_profile_id,
            label=f"{label}.deviceRecord",
            errors=errors,
        )
        if isinstance(derived_identity, Mapping):
            for identity_label, candidate in (
                ("QualificationSubject", subject_identity),
                ("QualificationRecord", record.get("pciIdentityMatch")),
            ):
                if candidate != derived_identity:
                    errors.append(
                        f"{label}.{identity_label}.pciIdentityMatch: exact "
                        "DeviceRecord projection mismatch"
                    )
        if isinstance(device_descriptor, Mapping) and device_descriptor.get(
            "recordDigest"
        ) != device.get("deviceRecordHash"):
            errors.append(f"{label}.deviceRecord.recordDigest: parsed mismatch")
        exact_device_tuple = {
            "deviceUid": device.get("deviceUid"),
            "deviceRecordHash": device.get("deviceRecordHash"),
        }
        for tuple_label, candidate in (
            ("classification", classification),
            ("QualificationRun", run),
            ("QualificationSubject", subject),
        ):
            for field, expected in exact_device_tuple.items():
                if candidate.get(field) != expected:
                    errors.append(
                        f"{label}.{tuple_label}.{field}: exact device mismatch"
                    )
    if isinstance(inventory, Mapping) and isinstance(device, Mapping):
        exact_input = {
            "hostId": inventory.get("hostId"),
            "hostEpoch": inventory.get("hostEpoch"),
            "bootId": inventory.get("kernelBootId"),
            "snapshotEpoch": inventory.get("snapshotEpoch"),
            "deviceUid": device.get("deviceUid"),
            "deviceRecordHash": device.get("deviceRecordHash"),
        }
        for field, expected in exact_input.items():
            if classification.get(field) != expected:
                errors.append(f"{label}.{field}: parsed inventory/device mismatch")
        if device.get("deviceRecordHash") not in inventory.get("deviceRecordDigests", []):
            errors.append(f"{label}.deviceRecordHash: absent from current HostSnapshot")

    pointer_receipt = classification.get("hostAuthorityPointerReceipt")
    pointer_key = None
    if isinstance(pointer_receipt, Mapping):
        pointer_key = _verify_history_signed_envelope(
            pointer_receipt,
            digest_field="receiptDigest",
            signature_field="signature",
            signer_field="signerKeyId",
            signed_time_field="observedAt",
            domain="QMAN-DIRECTPATH/HOST-AUTHORITY-POINTER-RECEIPT/V1",
            required_role="HOST_INVENTORY_EVIDENCE",
            trust=trust,
            evidence_git=evidence_git,
            root=root,
            label=f"{label}.hostAuthorityPointerReceipt",
            errors=errors,
        )
        pointer_exact = {
            "classificationId": classification.get("classificationId"),
            "inventorySnapshotRawSha256": (
                inventory_descriptor.get("sha256")
                if isinstance(inventory_descriptor, Mapping)
                else None
            ),
            "observedAt": classification.get("classifiedAt"),
        }
        for field, expected in pointer_exact.items():
            if pointer_receipt.get(field) != expected:
                errors.append(
                    f"{label}.hostAuthorityPointerReceipt.{field}: "
                    "classification mismatch"
                )
        authority_state = pointer_receipt.get("hostAuthorityState")
        if isinstance(authority_state, Mapping):
            run_snapshot = run.get("currentInventorySnapshot")
            state_exact = {
                "hostId": classification.get("hostId"),
                "hostEpoch": classification.get("hostEpoch"),
                "kernelBootId": classification.get("bootId"),
                "agentGeneration": (
                    inventory.get("agentGeneration")
                    if isinstance(inventory, Mapping)
                    else None
                ),
                "lastSnapshotEpoch": classification.get("snapshotEpoch"),
                "currentSnapshotContentHash": (
                    inventory.get("contentHash")
                    if isinstance(inventory, Mapping)
                    else None
                ),
                "resourceVersion": (
                    run_snapshot.get("hostAuthorityResourceVersion")
                    if isinstance(run_snapshot, Mapping)
                    else None
                ),
            }
            for field, expected in state_exact.items():
                if authority_state.get(field) != expected:
                    errors.append(
                        f"{label}.hostAuthorityPointerReceipt.hostAuthorityState."
                        f"{field}: current pointer mismatch"
                    )
            if authority_state.get("cooperationState") != "ONLINE_COOPERATIVE":
                errors.append(
                    f"{label}.hostAuthorityPointerReceipt.hostAuthorityState."
                    "cooperationState: expected ONLINE_COOPERATIVE"
                )
            last_observed = _parse_time(
                authority_state.get("lastObservedAt"),
                f"{label}.hostAuthorityPointerReceipt.hostAuthorityState."
                "lastObservedAt",
                errors,
            )
            receipt_observed = _parse_time(
                pointer_receipt.get("observedAt"),
                f"{label}.hostAuthorityPointerReceipt.observedAt",
                errors,
            )
            if (
                last_observed is not None
                and receipt_observed is not None
                and last_observed > receipt_observed
            ):
                errors.append(
                    f"{label}.hostAuthorityPointerReceipt.hostAuthorityState."
                    "lastObservedAt: postdates atomic read receipt"
                )
        else:
            errors.append(
                f"{label}.hostAuthorityPointerReceipt.hostAuthorityState: "
                "expected object"
            )
    else:
        errors.append(f"{label}.hostAuthorityPointerReceipt: expected signed object")

    context = classification.get("classificationContext")
    context_key = None
    if isinstance(context, Mapping):
        context_key = _verify_history_signed_envelope(
            context,
            digest_field="contextDigest",
            signature_field="signature",
            signer_field="signerKeyId",
            signed_time_field="classifiedAt",
            domain="QMAN-DIRECTPATH/DEVICE-CLASSIFICATION-CONTEXT/V1",
            required_role="QUALIFICATION_ENGINEERING",
            trust=trust,
            evidence_git=evidence_git,
            root=root,
            label=f"{label}.classificationContext",
            errors=errors,
        )
        exact_context = {
            "classificationId": classification.get("classificationId"),
            "targetRepositoryCommit": classification.get("targetRepositoryCommit"),
            "mappingCoreId": classification.get("mappingCoreId"),
            "portableContractSha256": classification.get("portableContractSha256"),
            "taxonomyDefinition": taxonomy_descriptor,
            "inventorySnapshot": inventory_descriptor,
            "deviceRecord": device_descriptor,
            "hostAuthorityPointerReceipt": pointer_receipt,
            "hostId": classification.get("hostId"),
            "hostEpoch": classification.get("hostEpoch"),
            "bootId": classification.get("bootId"),
            "snapshotEpoch": classification.get("snapshotEpoch"),
            "deviceUid": classification.get("deviceUid"),
            "deviceRecordHash": classification.get("deviceRecordHash"),
            "classifiedAt": classification.get("classifiedAt"),
            "keyRingVersion": classification.get("keyRingVersion"),
            "signerKeyId": classification.get("signerKeyId"),
            "signerRole": classification.get("signerRole"),
        }
        for field, expected in exact_context.items():
            if context.get(field) != expected:
                errors.append(f"{label}.classificationContext.{field}: record mismatch")
    else:
        errors.append(f"{label}.classificationContext: expected signed object")
    if isinstance(final_key, Mapping) and isinstance(context_key, Mapping) and final_key.get(
        "principalId"
    ) != context_key.get("principalId"):
        errors.append(f"{label}: context and final record signer principals differ")
    if isinstance(pointer_key, Mapping):
        pointer_principal = pointer_key.get("principalId")
        if (
            isinstance(context_key, Mapping)
            and pointer_principal == context_key.get("principalId")
        ) or (
            isinstance(final_key, Mapping)
            and pointer_principal == final_key.get("principalId")
        ):
            errors.append(
                f"{label}: pointer receipt and qualification signer principals "
                "must be independent"
            )

    classified_at = _parse_time(classification.get("classifiedAt"), f"{label}.classifiedAt", errors)
    signed_at = _parse_time(classification.get("signedAt"), f"{label}.signedAt", errors)
    taxonomy_issued = _parse_time(taxonomy.get("issuedAt"), f"{label}.taxonomy.issuedAt", errors)
    captured_at = (
        _parse_time(inventory.get("capturedAt"), f"{label}.inventory.capturedAt", errors)
        if isinstance(inventory, Mapping)
        else None
    )
    measurement_time = _parse_time(
        measurement_observed_at, f"{label}.measurementObservedAt", errors
    )
    if classified_at is not None:
        if taxonomy_issued is not None and classified_at < taxonomy_issued:
            errors.append(f"{label}.classifiedAt: predates taxonomy")
        if captured_at is not None and classified_at < captured_at:
            errors.append(f"{label}.classifiedAt: predates inventory snapshot")
    if classified_at is not None and signed_at is not None and classified_at >= signed_at:
        errors.append(f"{label}.signedAt: must strictly follow classification")
    if signed_at is not None and measurement_time is not None and signed_at > measurement_time:
        errors.append(f"{label}.signedAt: postdates QualificationMeasurement")

    taxonomy_rows = [
        item for item in taxonomy.get("archetypes", []) if isinstance(item, Mapping)
    ]
    trace = classification.get("ruleTrace")
    if not isinstance(trace, list) or not trace:
        errors.append(f"{label}.ruleTrace: expected non-empty prefix")
        trace = []
    for number, row in enumerate(trace):
        row_label = f"{label}.ruleTrace[{number}]"
        if not isinstance(row, Mapping):
            continue
        if number >= len(taxonomy_rows):
            errors.append(f"{row_label}: exceeds taxonomy")
            continue
        taxonomy_row = taxonomy_rows[number]
        for field in ("precedence", "archetype", "qualificationCaseProfileId"):
            if row.get(field) != taxonomy_row.get(field):
                errors.append(f"{row_label}.{field}: taxonomy prefix mismatch")
        expected_verdict = "MATCHED" if number == len(trace) - 1 else "NOT_MATCHED"
        if row.get("verdict") != expected_verdict:
            errors.append(f"{row_label}.verdict: expected {expected_verdict}")
        row_projection = {
            key: copy.deepcopy(value)
            for key, value in row.items()
            if key != "traceDigest"
        }
        expected_trace_digest = _canonical_digest(
            row_projection, f"{row_label}.traceDigest projection", errors
        )
        if row.get("traceDigest") != expected_trace_digest:
            errors.append(f"{row_label}.traceDigest: projection mismatch")
        pointers = row.get("evidencePointers")
        if not isinstance(pointers, list):
            errors.append(f"{row_label}.evidencePointers: expected array")
            pointers = []
        pointer_keys: list[bytes] = []
        for pointer_number, pointer in enumerate(pointers):
            pointer_label = f"{row_label}.evidencePointers[{pointer_number}]"
            if not isinstance(pointer, Mapping):
                continue
            try:
                pointer_keys.append(
                    canonical_json_bytes(
                        [
                            pointer.get("source"),
                            pointer.get("jsonPointer"),
                            pointer.get("observedValueDigest"),
                        ]
                    )
                )
            except (CanonicalizationError, TypeError, ValueError) as exc:
                errors.append(f"{pointer_label}: invalid canonical key: {exc}")
            source_document = (
                inventory if pointer.get("source") == "HOST_SNAPSHOT" else device
            )
            projected = (
                _json_pointer_projection(
                    source_document,
                    pointer.get("jsonPointer"),
                    f"{pointer_label}.jsonPointer",
                    errors,
                )
                if source_document is not None
                else None
            )
            projected_digest = _canonical_digest(
                projected, f"{pointer_label}.observedValueDigest projection", errors
            )
            if pointer.get("observedValueDigest") != projected_digest:
                errors.append(f"{pointer_label}.observedValueDigest: projection mismatch")
        if pointer_keys != sorted(pointer_keys) or len(pointer_keys) != len(set(pointer_keys)):
            errors.append(f"{row_label}.evidencePointers: non-canonical or duplicate")
    if trace:
        terminal = trace[-1]
        if isinstance(terminal, Mapping):
            if classification.get("deviceArchetype") != terminal.get("archetype"):
                errors.append(f"{label}.deviceArchetype: terminal trace mismatch")
            if classification.get("qualificationCaseProfileId") != terminal.get(
                "qualificationCaseProfileId"
            ):
                errors.append(f"{label}.qualificationCaseProfileId: terminal trace mismatch")
            if terminal.get("archetype") == "GENERIC_PCI" and len(trace) != 5:
                errors.append(f"{label}.ruleTrace: GENERIC_PCI requires full final prefix")

    if not all(
        isinstance(item, Mapping)
        for item in (taxonomy_descriptor, inventory_descriptor, device_descriptor, context)
    ) or inventory_blob is None or device_blob is None:
        errors.append(f"{label}: complete classifier replay inputs are unavailable")
        return
    assert isinstance(taxonomy_descriptor, Mapping)
    assert isinstance(inventory_descriptor, Mapping)
    assert isinstance(device_descriptor, Mapping)
    assert isinstance(context, Mapping)
    taxonomy_blob = (
        evidence_git.blob(
            taxonomy_descriptor.get("path"), f"{label}.taxonomyReplay.path", errors
        )
        if evidence_git is not None
        else None
    )
    if taxonomy_blob is None:
        errors.append(f"{label}: taxonomy replay bytes are unavailable")
        return
    try:
        context_blob = canonical_json_bytes(context)
    except (CanonicalizationError, TypeError, ValueError) as exc:
        errors.append(f"{label}.classificationContext: cannot form JCS input: {exc}")
        return
    classifier = taxonomy.get("classifier")
    environment = taxonomy.get("executionEnvironment")
    input_contracts = taxonomy.get("inputContracts")
    output_contract = taxonomy.get("outputContract")
    if not all(isinstance(item, Mapping) for item in (classifier, environment, input_contracts, output_contract)):
        errors.append(f"{label}: classifier replay interface is unavailable")
        return
    assert isinstance(classifier, Mapping)
    assert isinstance(environment, Mapping)
    assert isinstance(input_contracts, Mapping)
    assert isinstance(output_contract, Mapping)
    classifier_inputs = [
        {
            "role": "taxonomy",
            "sourcePathOrNull": taxonomy_descriptor.get("path"),
            "schemaRef": taxonomy_descriptor.get("schemaRef"),
            "schemaSha256": taxonomy_descriptor.get("schemaSha256"),
            "sha256": sha256(taxonomy_blob),
            "byteLength": len(taxonomy_blob),
            "mediaType": "application/json",
            "readOnly": True,
            "bytes": taxonomy_blob,
        },
        {
            "role": "hostSnapshot",
            "sourcePathOrNull": inventory_descriptor.get("path"),
            "schemaRef": inventory_descriptor.get("schemaRef"),
            "schemaSha256": inventory_descriptor.get("schemaSha256"),
            "sha256": sha256(inventory_blob),
            "byteLength": len(inventory_blob),
            "mediaType": "application/json",
            "readOnly": True,
            "bytes": inventory_blob,
        },
        {
            "role": "deviceRecord",
            "sourcePathOrNull": device_descriptor.get("path"),
            "schemaRef": device_descriptor.get("schemaRef"),
            "schemaSha256": device_descriptor.get("schemaSha256"),
            "sha256": sha256(device_blob),
            "byteLength": len(device_blob),
            "mediaType": "application/json",
            "readOnly": True,
            "bytes": device_blob,
        },
        {
            "role": "classificationContext",
            "sourcePathOrNull": None,
            "schemaRef": input_contracts.get("classificationContext", {}).get("schemaRef")
            if isinstance(input_contracts.get("classificationContext"), Mapping)
            else None,
            "schemaSha256": input_contracts.get("classificationContext", {}).get("schemaSha256")
            if isinstance(input_contracts.get("classificationContext"), Mapping)
            else None,
            "sha256": sha256(context_blob),
            "byteLength": len(context_blob),
            "mediaType": "application/json",
            "readOnly": True,
            "bytes": context_blob,
        },
    ]
    expected_output = copy.deepcopy(dict(classification))
    expected_output["signedAt"] = None
    expected_output["classificationDigest"] = None
    expected_output["signature"] = None
    runtime_binary = environment.get("runtimeBinary")
    runtime_identity = {
        "mode": environment.get("mode"),
        "runtimeBinarySha256": runtime_binary.get("sha256")
        if isinstance(runtime_binary, Mapping)
        else None,
        "dependencyLockSha256": environment.get("dependencyLock", {}).get("sha256")
        if isinstance(environment.get("dependencyLock"), Mapping)
        else None,
        "environmentManifestSha256": environment.get("environmentManifest", {}).get("sha256")
        if isinstance(environment.get("environmentManifest"), Mapping)
        else None,
    }
    _execute_signed_artifact_replay(
        consumer_kind="TAXONOMY_CLASSIFIER",
        consumer_protocol=classifier.get("protocol"),
        consumer_artifact_digest=taxonomy.get("definitionDigest"),
        consumer_manifest_descriptor=taxonomy_descriptor,
        interface_contract_digest=classifier.get("interfaceContractDigest"),
        target_repository_commit=taxonomy.get("targetRepositoryCommit"),
        mapping_core_id=taxonomy.get("mappingCoreId"),
        portable_contract_sha256=taxonomy.get("portableContractSha256"),
        target_architecture=architecture,
        runtime_identity=runtime_identity,
        closure=closure,
        inputs=classifier_inputs,
        evidence_root_artifacts=[],
        semantic_argv_order=[
            "taxonomy",
            "hostSnapshot",
            "deviceRecord",
            "classificationContext",
            "output",
        ],
        output_role="output",
        output_schema_ref=(
            "contracts/directpath-device-classification-record.schema.json"
        ),
        output_schema_sha256=output_contract.get("schemaSha256"),
        expected_output=expected_output,
        root=root,
        label=f"{label}.classifierReplay",
        errors=errors,
    )

def _validate_qualification_run_manifest(
    subject: Mapping[str, Any],
    record: Mapping[str, Any],
    bundles: Sequence[Mapping[str, Any]],
    *,
    trust: _TrustContext | None,
    root: Path,
    code_git: _GitView | None,
    evidence_git: _GitView | None,
    mapping: Mapping[str, Any] | None,
    label: str,
    errors: list[str],
) -> Mapping[str, Any] | None:
    descriptor = subject.get("qualificationRunManifest")
    blob = _typed_artifact_from_git(
        descriptor,
        evidence_git,
        root,
        label,
        errors,
        expected_schema_ref=(
            "contracts/directpath-qualification-run-manifest.schema.json"
        ),
        descriptor_fields=QUALIFICATION_RUN_DESCRIPTOR_FIELDS,
    )
    if not isinstance(descriptor, Mapping) or blob is None:
        return None
    if descriptor.get("mediaType") != "application/json":
        errors.append(f"{label}.mediaType: expected application/json")
    if descriptor.get("byteLength") != len(blob):
        errors.append(
            f"{label}.byteLength: declared {descriptor.get('byteLength')!r}, "
            f"actual {len(blob)}"
        )
    run = _load_json_bytes(blob, label, errors)
    if not isinstance(run, Mapping):
        return None
    if descriptor.get("runDigest") != run.get("runDigest"):
        errors.append(f"{label}.runDigest: parsed manifest mismatch")
    subject_issued = _parse_time(
        subject.get("issuedAt"), f"{label}.subject.issuedAt", errors
    )
    _verify_qualification_run_attestations(
        run,
        subject_issued_at=subject_issued,
        trust=trust,
        evidence_git=evidence_git,
        root=root,
        label=label,
        errors=errors,
    )

    exact_subject_fields = {
        "qualificationRunId": subject.get("qualificationRunId"),
        "hostId": subject.get("hostId"),
        "hostEpoch": subject.get("hostEpoch"),
        "bootId": subject.get("bootId"),
        "deviceUid": subject.get("deviceUid"),
        "deviceRecordHash": subject.get("deviceRecordHash"),
    }
    for field, expected in exact_subject_fields.items():
        if run.get(field) != expected:
            errors.append(f"{label}.{field}: QualificationSubject mismatch")
    if run.get("state") != "COMPLETE" or run.get(
        "evidenceGrade"
    ) != "E4-PHYSICAL-QUALIFICATION":
        errors.append(f"{label}: Subject requires COMPLETE E4 run")

    scenarios = [
        bundle.get("scenario")
        for bundle in bundles
        if isinstance(bundle.get("scenario"), Mapping)
    ]
    indexes = [
        bundle.get("index")
        for bundle in bundles
        if isinstance(bundle.get("index"), Mapping)
    ]
    targets = [
        scenario.get("targetBinding")
        for scenario in scenarios
        if isinstance(scenario, Mapping)
        and isinstance(scenario.get("targetBinding"), Mapping)
    ]
    target_field_map = {
        "targetRepositoryCommit": "repositoryCommit",
        "mappingCoreId": "mappingCoreId",
        "mappingCoreDigest": "integrationMapSha256",
        "portableContractSha256": "portableContractSha256",
    }
    for run_field, target_field in target_field_map.items():
        target_values = [target.get(target_field) for target in targets]
        if run_field == "targetRepositoryCommit":
            run_value = _normal_commit(
                run.get(run_field), f"{label}.{run_field}", errors
            )
            compared_values = [
                _normal_commit(value, f"{label}.Scenario.{target_field}", errors)
                for value in target_values
            ]
        else:
            run_value = run.get(run_field)
            compared_values = target_values
        if not target_values or any(value != run_value for value in compared_values):
            errors.append(f"{label}.{run_field}: E4 Scenario target mismatch")
    normalized_run_commit = _normal_commit(
        run.get("targetRepositoryCommit"), f"{label}.targetRepositoryCommit", errors
    )
    if code_git is not None and normalized_run_commit != code_git.commit:
        errors.append(f"{label}.targetRepositoryCommit: target checkout C mismatch")
    if isinstance(mapping, Mapping):
        if run.get("mappingCoreId") != mapping.get("mappingCoreId"):
            errors.append(f"{label}.mappingCoreId: detached mapping mismatch")
        if run.get("mappingCoreDigest") != mapping.get("scenarioBindingDigest"):
            errors.append(f"{label}.mappingCoreDigest: detached mapping digest mismatch")

    runtime = subject.get("kernelQemuFirmwareBackend")
    platform = run.get("platformProfile")
    if isinstance(runtime, Mapping) and isinstance(platform, Mapping):
        platform_id = runtime.get("platformProfileId")
        expected_platform_digest = _derive_platform_profile_digest(
            root, platform_id, f"{label}.platformProfile", errors
        )
        policy_blob = _worktree_bytes(
            root,
            "contracts/compatibility-profile-policy.json",
            f"{label}.platformProfile.compatibilityPolicyPath",
            errors,
        )
        if platform.get("platformProfileId") != platform_id:
            errors.append(f"{label}.platformProfile.platformProfileId: runtime mismatch")
        if platform.get("platformProfileDigest") != subject.get(
            "platformProfileHash"
        ) or platform.get("platformProfileDigest") != expected_platform_digest:
            errors.append(f"{label}.platformProfile.platformProfileDigest: mismatch")
        if (
            policy_blob is not None
            and platform.get("compatibilityPolicySha256") != sha256(policy_blob)
        ):
            errors.append(
                f"{label}.platformProfile.compatibilityPolicySha256: policy mismatch"
            )
        for target in targets:
            if target.get("platformProfileDigest") != platform.get(
                "platformProfileDigest"
            ):
                errors.append(f"{label}.platformProfile: Scenario target mismatch")
    else:
        errors.append(f"{label}: runtime/platform profile is unavailable")

    backend = run.get("backendProfile")
    if isinstance(runtime, Mapping) and isinstance(backend, Mapping):
        expected_backend_digest = _canonical_digest(
            runtime, f"{label}.backendProfileDigest projection", errors
        )
        backend_exact = {
            "backendFamily": runtime.get("backendFamily"),
            "configuredIommuType": runtime.get("configuredIommuType"),
            "backendProfileDigest": expected_backend_digest,
        }
        for field, expected in backend_exact.items():
            if backend.get(field) != expected:
                errors.append(f"{label}.backendProfile.{field}: runtime mismatch")
        for target in targets:
            if target.get("backendProfileDigest") != backend.get(
                "backendProfileDigest"
            ):
                errors.append(f"{label}.backendProfile: Scenario target mismatch")
    else:
        errors.append(f"{label}: runtime/backend profile is unavailable")

    snapshot_descriptor = run.get("currentInventorySnapshot")
    _snapshot_blob, snapshot = _resolve_pinned_json_descriptor(
        snapshot_descriptor,
        expected_schema_ref=(
            "contracts/directpath-portable-hash-subjects.schema.json#/$defs/hostSnapshot"
        ),
        evidence_git=evidence_git,
        root=root,
        label=f"{label}.currentInventorySnapshot",
        errors=errors,
    )
    if isinstance(snapshot_descriptor, Mapping) and isinstance(snapshot, Mapping):
        snapshot_exact = {
            "snapshotEpoch": "snapshotEpoch",
            "agentGeneration": "agentGeneration",
            "hostAuthorityResourceVersion": "hostAuthorityResourceVersion",
            "inventorySnapshotDigest": "contentHash",
            "observedAt": "capturedAt",
        }
        for descriptor_field, snapshot_field in snapshot_exact.items():
            if snapshot_descriptor.get(descriptor_field) != snapshot.get(snapshot_field):
                errors.append(
                    f"{label}.currentInventorySnapshot.{descriptor_field}: "
                    "parsed HostSnapshot mismatch"
                )
        if snapshot_descriptor.get("inventorySnapshotDigest") != subject.get(
            "inventorySnapshotDigest"
        ):
            errors.append(
                f"{label}.currentInventorySnapshot.inventorySnapshotDigest: "
                "Subject mismatch"
            )
        if run.get("deviceRecordHash") not in snapshot.get(
            "deviceRecordDigests", []
        ):
            errors.append(
                f"{label}.currentInventorySnapshot: exact deviceRecordHash "
                "is absent"
            )
        host_exact = {
            "hostId": run.get("hostId"),
            "hostEpoch": run.get("hostEpoch"),
            "kernelBootId": run.get("bootId"),
        }
        for field, expected in host_exact.items():
            if snapshot.get(field) != expected:
                errors.append(
                    f"{label}.currentInventorySnapshot.{field}: run mismatch"
                )
        _verify_history_signed_envelope(
            snapshot,
            digest_field="contentHash",
            signature_field="signature",
            signer_field="signerKeyId",
            signed_time_field="capturedAt",
            domain="QMAN-DIRECTPATH/HOST-SNAPSHOT/V1",
            required_role="HOST_INVENTORY_EVIDENCE",
            trust=trust,
            evidence_git=evidence_git,
            root=root,
            label=f"{label}.currentInventorySnapshot",
            errors=errors,
        )
        snapshot_raw_hash = snapshot_descriptor.get("sha256")
        for number, bundle in enumerate(bundles):
            artifacts = bundle.get("artifacts")
            artifact = (
                artifacts.get(snapshot_raw_hash)
                if isinstance(artifacts, Mapping)
                and isinstance(snapshot_raw_hash, str)
                else None
            )
            if (
                not isinstance(artifact, Mapping)
                or artifact.get("artifactType") != "TYPED_ENTITY"
                or artifact.get("evidenceRole") != "INVENTORY_SNAPSHOT"
            ):
                errors.append(
                    f"{label}.currentInventorySnapshot: E4[{number}] lacks the "
                    "exact raw HostSnapshot artifact"
                )

    request, definition = _validate_qualification_run_request(
        run.get("orchestratorRequest"),
        run=run,
        subject=subject,
        record=record,
        code_git=code_git,
        evidence_git=evidence_git,
        root=root,
        mapping=mapping,
        trust=trust,
        label=f"{label}.orchestratorRequest",
        errors=errors,
    )

    workload_result = None
    if isinstance(request, Mapping) and isinstance(definition, Mapping):
        workload_result = _validate_qualification_workload_result(
            run.get("workloadResult"),
            request=request,
            definition=definition,
            run=run,
            subject=subject,
            code_git=code_git,
            evidence_git=evidence_git,
            root=root,
            mapping=mapping,
            trust=trust,
            label=f"{label}.workloadResult",
            errors=errors,
        )

        expected_correlation = {
            "evidenceGrade": "E4-PHYSICAL-QUALIFICATION",
            "qualificationRunIdOrNull": request.get("qualificationRunId"),
            "qualificationRunRequestDigestOrNull": request.get("requestDigest"),
            "qualificationRunRequestNonceDigestOrNull": (
                _qualification_request_nonce_digest(
                    request.get("requestNonce"),
                    f"{label}.orchestratorRequest.requestNonceCorrelation",
                    errors,
                )
            ),
        }
        for number, bundle in enumerate(bundles):
            scenario = bundle.get("scenario")
            index = bundle.get("index")
            result = (
                scenario.get("executionResult")
                if isinstance(scenario, Mapping)
                else None
            )
            target = (
                scenario.get("targetBinding")
                if isinstance(scenario, Mapping)
                else None
            )
            for object_name, candidate in (
                ("Scenario.targetBinding", target),
                ("Scenario.executionResult", result),
                ("ExecutionEvidenceIndex", index),
            ):
                if not isinstance(candidate, Mapping):
                    errors.append(
                        f"{label}.E4[{number}].{object_name}: correlation object missing"
                    )
                    continue
                for field, expected in expected_correlation.items():
                    if candidate.get(field) != expected:
                        errors.append(
                            f"{label}.E4[{number}].{object_name}.{field}: "
                            "QualificationRunRequest mismatch"
                        )

    run_started = _parse_time(run.get("startedAt"), f"{label}.startedAt", errors)
    run_finished = _parse_time(run.get("finishedAt"), f"{label}.finishedAt", errors)
    if run_started is not None and run_finished is not None and run_started >= run_finished:
        errors.append(f"{label}: startedAt must strictly precede finishedAt")
    monotonic = run.get("monotonicTiming")
    if isinstance(monotonic, Mapping):
        try:
            monotonic_started = int(monotonic.get("startedNanoseconds"))
            monotonic_finished = int(monotonic.get("finishedNanoseconds"))
            monotonic_duration = int(monotonic.get("durationNanoseconds"))
        except (TypeError, ValueError):
            errors.append(f"{label}.monotonicTiming: invalid decimal nanoseconds")
        else:
            if (
                monotonic_finished <= monotonic_started
                or monotonic_duration != monotonic_finished - monotonic_started
            ):
                errors.append(f"{label}.monotonicTiming: inconsistent duration")

    declared_cores = _unique_strings(
        run.get("scenarioExecutionCoreDigests"),
        f"{label}.scenarioExecutionCoreDigests",
        errors,
    )
    subject_cores = _unique_strings(
        subject.get("scenarioExecutionCoreDigests"),
        f"{label}.subject.scenarioExecutionCoreDigests",
        errors,
    )
    index_cores = [
        index.get("scenarioExecutionCoreDigest")
        for index in indexes
        if isinstance(index.get("scenarioExecutionCoreDigest"), str)
    ]
    if set(declared_cores) != set(subject_cores) or set(declared_cores) != set(
        index_cores
    ) or len(index_cores) != len(set(index_cores)):
        errors.append(f"{label}.scenarioExecutionCoreDigests: closure mismatch")
    _require_canonical_set_order(
        run.get("scenarioExecutionCoreDigests"),
        f"{label}.scenarioExecutionCoreDigests",
        errors,
    )
    for number, index in enumerate(indexes):
        index_started = _parse_time(
            index.get("runStartedAt"), f"{label}.E4[{number}].runStartedAt", errors
        )
        index_finished = _parse_time(
            index.get("runFinishedAt"), f"{label}.E4[{number}].runFinishedAt", errors
        )
        if (
            run_started is not None
            and index_started is not None
            and index_started < run_started
        ) or (
            run_finished is not None
            and index_finished is not None
            and index_finished > run_finished
        ):
            errors.append(f"{label}.E4[{number}]: core lies outside run interval")

    measurement_descriptors = run.get("qualificationMeasurements")
    if not isinstance(measurement_descriptors, list):
        measurement_descriptors = []
    subject_sources = subject.get("measurementSources")
    if not isinstance(subject_sources, list):
        subject_sources = []
    subject_sources_by_digest = {
        item.get("measurementDigest"): item
        for item in subject_sources
        if isinstance(item, Mapping)
        and isinstance(item.get("measurementDigest"), str)
    }
    descriptor_order: list[bytes] = []
    seen_paths: set[str] = set()
    seen_hashes: set[str] = set()
    seen_ids: set[str] = set()
    seen_digests: set[str] = set()
    measured_core_values: set[str] = set()
    field_counts: dict[str, int] = {}
    measurement_schema = "contracts/directpath-qualification-measurement.schema.json"
    for number, measurement_descriptor in enumerate(measurement_descriptors):
        measurement_label = f"{label}.qualificationMeasurements[{number}]"
        if not isinstance(measurement_descriptor, Mapping):
            continue
        try:
            descriptor_order.append(
                canonical_json_bytes(
                    [
                        measurement_descriptor.get("subjectField"),
                        measurement_descriptor.get("sourceKind"),
                        measurement_descriptor.get("measurementDigest"),
                    ]
                )
            )
        except (CanonicalizationError, TypeError, ValueError) as exc:
            errors.append(f"{measurement_label}: invalid order key: {exc}")
        for field, seen in (
            ("measurementPath", seen_paths),
            ("measurementSha256", seen_hashes),
            ("measurementId", seen_ids),
            ("measurementDigest", seen_digests),
        ):
            value = measurement_descriptor.get(field)
            if not isinstance(value, str):
                continue
            if value in seen:
                errors.append(f"{measurement_label}.{field}: duplicate identity")
            seen.add(value)
        source = subject_sources_by_digest.get(
            measurement_descriptor.get("measurementDigest")
        ) if isinstance(measurement_descriptor.get("measurementDigest"), str) else None
        if not isinstance(source, Mapping):
            errors.append(f"{measurement_label}: absent from QualificationSubject")
        else:
            descriptor_source_fields = {
                "qualificationRunId": "qualificationRunId",
                "subjectField": "subjectField",
                "sourceKind": "sourceKind",
                "measurementPath": "measurementPath",
                "measurementSha256": "measurementSha256",
                "schemaRef": "schemaRef",
                "schemaSha256": "schemaSha256",
                "measurementDigest": "measurementDigest",
                "observedAt": "observedAt",
                "hostId": "hostId",
                "hostEpoch": "hostEpoch",
                "bootId": "bootId",
                "deviceUid": "deviceUid",
                "deviceRecordHash": "deviceRecordHash",
            }
            for descriptor_field, source_field in descriptor_source_fields.items():
                if measurement_descriptor.get(descriptor_field) != source.get(source_field):
                    errors.append(
                        f"{measurement_label}.{descriptor_field}: Subject source mismatch"
                    )
        measurement_blob, measurement = _resolve_pinned_json_descriptor(
            {
                "path": measurement_descriptor.get("measurementPath"),
                "sha256": measurement_descriptor.get("measurementSha256"),
                "byteLength": measurement_descriptor.get("measurementByteLength"),
                "mediaType": measurement_descriptor.get("mediaType"),
                "schemaRef": measurement_descriptor.get("schemaRef"),
                "schemaSha256": measurement_descriptor.get("schemaSha256"),
            },
            expected_schema_ref=measurement_schema,
            evidence_git=evidence_git,
            root=root,
            label=measurement_label,
            errors=errors,
        )
        del measurement_blob
        if not isinstance(measurement, Mapping):
            continue
        parsed_fields = {
            "measurementId": "measurementId",
            "qualificationRunId": "qualificationRunId",
            "subjectField": "subjectField",
            "sourceKind": "sourceKind",
            "measurementDigest": "measurementDigest",
            "signerRole": "signerRole",
            "observedAt": "observedAt",
            "hostId": "hostId",
            "hostEpoch": "hostEpoch",
            "bootId": "bootId",
            "deviceUid": "deviceUid",
            "deviceRecordHash": "deviceRecordHash",
        }
        for descriptor_field, parsed_field in parsed_fields.items():
            if measurement_descriptor.get(descriptor_field) != measurement.get(
                parsed_field
            ):
                errors.append(
                    f"{measurement_label}.{descriptor_field}: parsed measurement mismatch"
                )
        for tuple_field in (
            "qualificationRunId",
            "hostId",
            "hostEpoch",
            "bootId",
            "deviceUid",
            "deviceRecordHash",
        ):
            if measurement.get(tuple_field) != run.get(tuple_field):
                errors.append(f"{measurement_label}.{tuple_field}: run mismatch")
        _verify_history_signed_envelope(
            measurement,
            digest_field="measurementDigest",
            signature_field="signature",
            signer_field="signerKeyId",
            signed_time_field="observedAt",
            domain="QMAN-DIRECTPATH/QUALIFICATION-MEASUREMENT/V1",
            required_role=measurement.get("signerRole") if isinstance(
                measurement.get("signerRole"), str
            ) else "INVALID",
            trust=trust,
            evidence_git=evidence_git,
            root=root,
            label=measurement_label,
            errors=errors,
        )
        observed = _parse_time(
            measurement.get("observedAt"), f"{measurement_label}.observedAt", errors
        )
        if (
            run_started is not None
            and observed is not None
            and observed < run_started
        ) or (
            run_finished is not None
            and observed is not None
            and observed > run_finished
        ):
            errors.append(f"{measurement_label}.observedAt: outside run interval")
        subject_field = measurement.get("subjectField")
        if isinstance(subject_field, str):
            field_counts[subject_field] = field_counts.get(subject_field, 0) + 1
        if subject_field == "caseExecution":
            core_value = measurement.get("measuredValue")
            if isinstance(core_value, str):
                measured_core_values.add(core_value)
            if measurement.get("inventorySnapshotDigestOrNull") is not None:
                errors.append(f"{measurement_label}: case measurement inventory must be null")
        elif isinstance(snapshot_descriptor, Mapping) and measurement.get(
            "inventorySnapshotDigestOrNull"
        ) != snapshot_descriptor.get("inventorySnapshotDigest"):
            errors.append(f"{measurement_label}: inventory content hash mismatch")
    if descriptor_order != sorted(descriptor_order) or len(descriptor_order) != len(
        set(descriptor_order)
    ):
        errors.append(f"{label}.qualificationMeasurements: non-canonical/duplicate")
    if set(subject_sources_by_digest) != seen_digests:
        errors.append(f"{label}.qualificationMeasurements: Subject bijection mismatch")
    for field in (
        "pciIdentityMatch",
        "deviceArchetype",
        "deviceFirmwareAndRom",
        "kernelQemuFirmwareBackend",
        "iommuInterruptResetProviders",
        "guestDriverAndWorkload",
        "deviceTraits",
    ):
        if field_counts.get(field) != 1:
            errors.append(f"{label}.qualificationMeasurements: expected one {field}")
    if measured_core_values != set(declared_cores) or field_counts.get(
        "caseExecution"
    ) != len(declared_cores):
        errors.append(f"{label}.qualificationMeasurements: core bijection mismatch")

    del workload_result
    return run


def _validate_qualification_subject_manifest(
    record: Mapping[str, Any],
    bundles: list[Mapping[str, Any]],
    case_registry: Mapping[str, Any] | None,
    trust: _TrustContext | None,
    root: Path,
    code_git: _GitView | None,
    evidence_git: _GitView | None,
    mapping: Mapping[str, Any] | None,
    label: str,
    errors: list[str],
) -> None:
    subjects = [bundle.get("subject") for bundle in bundles]
    if not subjects or not all(isinstance(item, Mapping) for item in subjects):
        errors.append(f"{label}: every E4 index must resolve one measured subject")
        return
    subject = subjects[0]
    assert isinstance(subject, Mapping)
    subject_blobs = [bundle.get("subjectBlob") for bundle in bundles]
    if not all(isinstance(blob, bytes) for blob in subject_blobs) or len(
        set(subject_blobs)
    ) != 1:
        errors.append(
            f"{label}: every E4 index must embed byte-identical QualificationSubject"
        )
    _validate_closed_json_schema_instance(
        subject,
        root,
        "contracts/directpath-qualification-subject-manifest.schema.json",
        f"{label}.QualificationSubject",
        errors,
    )
    _verify_signed_envelope(
        subject,
        digest_field="manifestDigest",
        signature_field="signature",
        signer_field="signerKeyId",
        signed_time_field="issuedAt",
        domain="QMAN-DIRECTPATH/QUALIFICATION-SUBJECT-MANIFEST/V1",
        required_role="HOST_INVENTORY_EVIDENCE",
        trust=trust,
        label=f"{label}.QualificationSubject",
        errors=errors,
    )
    if record.get("qualificationSubjectManifestDigest") != subject.get(
        "manifestDigest"
    ):
        errors.append(
            f"{label}: qualificationSubjectManifestDigest does not equal signed subject"
        )
    exact_fields = {
        "qualificationRecordId": "qualificationRecordId",
        "platformProfileHash": "platformProfileHash",
        "qualificationCaseMatrixSha256": "qualificationCaseMatrixSha256",
        "pciIdentityMatch": "pciIdentityMatch",
        "deviceArchetype": "deviceArchetype",
        "deviceTraits": "deviceTraits",
        "deviceFirmwareAndRom": "deviceFirmwareAndRom",
        "kernelQemuFirmwareBackend": "kernelQemuFirmwareBackend",
        "iommuInterruptResetProviders": "iommuInterruptResetProviders",
        "guestDriverAndWorkload": "guestDriverAndWorkload",
        "caseIds": "caseIds",
        "derivedExactQualificationKey": "exactQualificationKey",
    }
    for subject_field, record_field in exact_fields.items():
        if subject.get(subject_field) != record.get(record_field):
            errors.append(
                f"{label}.QualificationSubject.{subject_field}: must byte-equal "
                f"QualificationRecord.{record_field}"
            )

    indexes = [
        bundle.get("index")
        for bundle in bundles
        if isinstance(bundle.get("index"), Mapping)
    ]
    _qualification_run = _validate_qualification_run_manifest(
        subject,
        record,
        bundles,
        trust=trust,
        root=root,
        code_git=code_git,
        evidence_git=evidence_git,
        mapping=mapping,
        label=f"{label}.QualificationRunManifest",
        errors=errors,
    )
    core_digests = [
        index.get("scenarioExecutionCoreDigest")
        for index in indexes
        if isinstance(index.get("scenarioExecutionCoreDigest"), str)
    ]
    declared_cores = _unique_strings(
        subject.get("scenarioExecutionCoreDigests"),
        f"{label}.QualificationSubject.scenarioExecutionCoreDigests",
        errors,
    )
    _require_canonical_set_order(
        subject.get("scenarioExecutionCoreDigests"),
        f"{label}.QualificationSubject.scenarioExecutionCoreDigests",
        errors,
    )
    if set(declared_cores) != set(core_digests) or len(core_digests) != len(
        set(core_digests)
    ):
        errors.append(
            f"{label}: subject cores and E4 indexes must form an exact bijection"
        )
    index_case_ids = [
        index.get("caseId")
        for index in indexes
        if isinstance(index.get("caseId"), str)
    ]
    subject_case_values = _unique_strings(
        subject.get("caseIds"),
        f"{label}.QualificationSubject.caseIds",
        errors,
    )
    if set(index_case_ids) != set(subject_case_values):
        errors.append(
            f"{label}: E4 indexes and measured Case IDs must form an exact bijection"
        )
    for bundle in bundles:
        index = bundle.get("index")
        if not isinstance(index, Mapping):
            continue
        if index.get("evidenceGrade") != "E4-PHYSICAL-QUALIFICATION":
            errors.append(f"{label}: subject may bind only E4 indexes")
        embedded_subject = bundle.get("subject")
        if not isinstance(embedded_subject, Mapping) or embedded_subject.get(
            "manifestDigest"
        ) != subject.get("manifestDigest"):
            errors.append(f"{label}: E4 index embeds a different subject digest")

    registry_by_id = {
        item.get("caseId"): item
        for item in (
            case_registry.get("records", [])
            if isinstance(case_registry, Mapping)
            else []
        )
        if isinstance(item, Mapping)
    }
    subject_case_ids = set(subject_case_values)
    for case_id in sorted(subject_case_ids):
        case = registry_by_id.get(case_id)
        classification = case.get("classification") if isinstance(case, Mapping) else None
        if not isinstance(classification, Mapping) or (
            classification.get("scope"), classification.get("status")
        ) != ("PRODUCT", "EXECUTABLE"):
            errors.append(
                f"{label}: qualification Case {case_id} is not PRODUCT/EXECUTABLE"
            )
            continue
        missing_dependencies = set(classification.get("dependsOnCaseIds", [])) - subject_case_ids
        if missing_dependencies:
            errors.append(
                f"{label}: qualification Case {case_id} lacks dependency closure "
                f"{sorted(missing_dependencies)}"
            )

    all_artifacts: dict[str, list[tuple[Mapping[str, Any], bytes, Mapping[str, Any]]]] = {}
    for bundle in bundles:
        index = bundle.get("index")
        artifacts = bundle.get("artifacts")
        blobs = bundle.get("blobs")
        if not isinstance(index, Mapping) or not isinstance(artifacts, Mapping) or not isinstance(blobs, Mapping):
            continue
        for digest, artifact in artifacts.items():
            blob = blobs.get(digest)
            if isinstance(digest, str) and isinstance(artifact, Mapping) and isinstance(blob, bytes):
                all_artifacts.setdefault(digest, []).append((artifact, blob, index))

    inventory_digest = subject.get("inventorySnapshotDigest")
    inventory_raw_hashes: set[str] = set()
    inventory_documents_by_raw: dict[str, Mapping[str, Any]] = {}
    inventory_schema_ref = (
        "contracts/directpath-portable-hash-subjects.schema.json#/$defs/hostSnapshot"
    )
    for raw_digest, locations in all_artifacts.items():
        for artifact, blob, _ in locations:
            if (
                artifact.get("artifactType") != "TYPED_ENTITY"
                or artifact.get("evidenceRole") != "INVENTORY_SNAPSHOT"
                or artifact.get("iterationRunIdOrNull") is not None
            ):
                continue
            snapshot = _load_json_bytes(
                blob, f"{label}.HostSnapshot[{raw_digest}]", errors
            )
            if not isinstance(snapshot, Mapping):
                continue
            _validate_closed_json_schema_instance(
                snapshot,
                root,
                inventory_schema_ref,
                f"{label}.HostSnapshot[{raw_digest}]",
                errors,
            )
            if snapshot.get("contentHash") != inventory_digest:
                continue
            inventory_raw_hashes.add(raw_digest)
            inventory_documents_by_raw.setdefault(raw_digest, snapshot)
            _verify_history_signed_envelope(
                snapshot,
                digest_field="contentHash",
                signature_field="signature",
                signer_field="signerKeyId",
                signed_time_field="capturedAt",
                domain="QMAN-DIRECTPATH/HOST-SNAPSHOT/V1",
                required_role="HOST_INVENTORY_EVIDENCE",
                trust=trust,
                evidence_git=evidence_git,
                root=root,
                label=f"{label}.HostSnapshot[{raw_digest}]",
                errors=errors,
            )
            snapshot_subject_fields = {
                "hostId": subject.get("hostId"),
                "hostEpoch": subject.get("hostEpoch"),
                "kernelBootId": subject.get("bootId"),
            }
            for snapshot_field, expected in snapshot_subject_fields.items():
                if snapshot.get(snapshot_field) != expected:
                    errors.append(
                        f"{label}.HostSnapshot[{raw_digest}].{snapshot_field}: "
                        "QualificationSubject mismatch"
                    )
    if len(inventory_raw_hashes) != 1:
        errors.append(
            f"{label}: inventorySnapshotDigest must resolve exactly one signed "
            f"HostSnapshot raw artifact, found {len(inventory_raw_hashes)}"
        )
    current_inventory = (
        inventory_documents_by_raw.get(next(iter(inventory_raw_hashes)))
        if len(inventory_raw_hashes) == 1
        else None
    )
    for bundle_number, bundle in enumerate(bundles):
        artifacts = bundle.get("artifacts")
        bundle_inventory_hashes = (
            inventory_raw_hashes & set(artifacts)
            if isinstance(artifacts, Mapping)
            else set()
        )
        if len(bundle_inventory_hashes) != 1:
            errors.append(
                f"{label}.E4[{bundle_number}]: current HostSnapshot raw artifact "
                "is not bound exactly once by this execution index"
            )

    source_specs = {
        "pciIdentityMatch": (
            "HOST_INVENTORY",
            "HOST_INVENTORY_EVIDENCE",
            {"HOST_INVENTORY_RECORD", "DEVICE_INVENTORY_RECORD"},
        ),
        "deviceTraits": (
            "HOST_INVENTORY",
            "HOST_INVENTORY_EVIDENCE",
            {"HOST_INVENTORY_RECORD", "DEVICE_INVENTORY_RECORD"},
        ),
        "deviceArchetype": (
            "QUALIFICATION_TAXONOMY_CLASSIFICATION",
            "QUALIFICATION_ENGINEERING",
            {"QUALIFICATION_TAXONOMY_RECORD"},
        ),
        "deviceFirmwareAndRom": (
            "FIRMWARE_READBACK",
            "HOST_INVENTORY_EVIDENCE",
            {"FIRMWARE_OR_ROM_READBACK"},
        ),
        "kernelQemuFirmwareBackend": (
            "RUNTIME_BINARY_MEASUREMENT",
            "HOST_INVENTORY_EVIDENCE",
            {"RUNTIME_BINARY", "RUNTIME_VERSION_READBACK"},
        ),
        "iommuInterruptResetProviders": (
            "KERNEL_PROVIDER_READBACK",
            "HOST_INVENTORY_EVIDENCE",
            {"KERNEL_PROVIDER_READBACK"},
        ),
        "guestDriverAndWorkload": (
            "GUEST_ATTESTED_READBACK",
            "HOST_INVENTORY_EVIDENCE",
            {"GUEST_ATTESTATION", "WORKLOAD_RESULT"},
        ),
        "caseExecution": (
            "SCENARIO_EXECUTION_CORE",
            "TEST_EVIDENCE",
            {"SCENARIO_EXECUTION_CORE_INPUT"},
        ),
    }
    sources = subject.get("measurementSources")
    if not isinstance(sources, list):
        sources = []
    source_order: list[bytes] = []
    sources_by_field: dict[str, list[Mapping[str, Any]]] = {}
    measured_cores: list[str] = []
    measurement_digests: set[str] = set()
    evidence_hash_owners: dict[str, set[tuple[Any, Any]]] = {}
    inventory_binding_hashes: dict[str, set[str]] = {}
    device_bindings_by_field: dict[str, list[Mapping[str, Any]]] = {}
    pending_classifications: list[tuple[Mapping[str, Any], Any, Any, str]] = []
    workload_result_hashes: set[str] = set()
    measurement_schema_ref = "contracts/directpath-qualification-measurement.schema.json"
    measurement_schema_blob = _worktree_bytes(
        root, measurement_schema_ref, f"{label}.QualificationMeasurement.schema", errors
    )
    subject_issued = _parse_time(
        subject.get("issuedAt"), f"{label}.QualificationSubject.issuedAt", errors
    )
    for number, source in enumerate(sources):
        source_label = f"{label}.QualificationSubject.measurementSources[{number}]"
        if not isinstance(source, Mapping):
            continue
        subject_field = source.get("subjectField")
        if isinstance(subject_field, str):
            sources_by_field.setdefault(subject_field, []).append(source)
        try:
            source_order.append(
                canonical_json_bytes(
                    [
                        subject_field,
                        source.get("sourceKind"),
                        source.get("measurementDigest"),
                    ]
                )
            )
        except (CanonicalizationError, TypeError, ValueError) as exc:
            errors.append(f"{source_label}: invalid order key: {exc}")
        for tuple_field in (
            "qualificationRunId",
            "hostId",
            "hostEpoch",
            "bootId",
            "deviceUid",
            "deviceRecordHash",
        ):
            if source.get(tuple_field) != subject.get(tuple_field):
                errors.append(f"{source_label}.{tuple_field}: subject mismatch")
        observed = _parse_time(source.get("observedAt"), f"{source_label}.observedAt", errors)
        if observed is not None and subject_issued is not None and observed > subject_issued:
            errors.append(f"{source_label}.observedAt: postdates signed subject")
        spec = source_specs.get(subject_field)
        if spec is None:
            errors.append(f"{source_label}.subjectField: unknown measured field")
            continue
        expected_kind, expected_role, expected_evidence_roles = spec
        if source.get("sourceKind") != expected_kind:
            errors.append(f"{source_label}.sourceKind: expected {expected_kind}")
        if source.get("schemaRef") != measurement_schema_ref:
            errors.append(f"{source_label}.schemaRef: fixed measurement schema required")
        _check_blob_hash(
            measurement_schema_blob,
            source.get("schemaSha256"),
            f"{source_label}.schema",
            errors,
        )
        measurement_blob = (
            evidence_git.blob(
                source.get("measurementPath"),
                f"{source_label}.measurementPath",
                errors,
            )
            if evidence_git is not None
            else None
        )
        _check_blob_hash(
            measurement_blob,
            source.get("measurementSha256"),
            f"{source_label}.measurement",
            errors,
        )
        measurement = (
            _load_json_bytes(measurement_blob, f"{source_label}.measurement", errors)
            if measurement_blob is not None
            else None
        )
        if not isinstance(measurement, Mapping):
            continue
        _validate_closed_json_schema_instance(
            measurement,
            root,
            measurement_schema_ref,
            f"{source_label}.measurement",
            errors,
        )
        descriptor_fields = {
            "qualificationRunId": "qualificationRunId",
            "subjectField": "subjectField",
            "sourceKind": "sourceKind",
            "measurementDigest": "measurementDigest",
            "observedAt": "observedAt",
            "hostId": "hostId",
            "hostEpoch": "hostEpoch",
            "bootId": "bootId",
            "deviceUid": "deviceUid",
            "deviceRecordHash": "deviceRecordHash",
        }
        for descriptor_field, measurement_field in descriptor_fields.items():
            if source.get(descriptor_field) != measurement.get(measurement_field):
                errors.append(
                    f"{source_label}.{descriptor_field}: parsed measurement mismatch"
                )
        if source.get("valueProjection") != "/measuredValue":
            errors.append(f"{source_label}.valueProjection: expected /measuredValue")
        for tuple_field in (
            "qualificationRunId",
            "hostId",
            "hostEpoch",
            "bootId",
            "deviceUid",
            "deviceRecordHash",
        ):
            if measurement.get(tuple_field) != subject.get(tuple_field):
                errors.append(
                    f"{source_label}.measurement.{tuple_field}: subject mismatch"
                )
        if measurement.get("signerRole") != expected_role:
            errors.append(f"{source_label}.measurement.signerRole: expected {expected_role}")
        _verify_history_signed_envelope(
            measurement,
            digest_field="measurementDigest",
            signature_field="signature",
            signer_field="signerKeyId",
            signed_time_field="observedAt",
            domain="QMAN-DIRECTPATH/QUALIFICATION-MEASUREMENT/V1",
            required_role=expected_role,
            trust=trust,
            evidence_git=evidence_git,
            root=root,
            label=f"{source_label}.measurement",
            errors=errors,
        )
        measurement_digest = measurement.get("measurementDigest")
        if isinstance(measurement_digest, str):
            if measurement_digest in measurement_digests:
                errors.append(f"{source_label}.measurementDigest: duplicate measurement")
            measurement_digests.add(measurement_digest)
        measured_value = measurement.get("measuredValue")
        if subject_field == "caseExecution":
            if measurement.get("inventorySnapshotDigestOrNull") is not None:
                errors.append(f"{source_label}: caseExecution inventory digest must be null")
            if not isinstance(measured_value, str) or measured_value not in set(
                declared_cores
            ):
                errors.append(f"{source_label}: measured core is not declared")
            else:
                measured_cores.append(measured_value)
        else:
            if measurement.get("inventorySnapshotDigestOrNull") != inventory_digest:
                errors.append(f"{source_label}: current inventory snapshot mismatch")
            if measured_value != subject.get(subject_field):
                errors.append(f"{source_label}: /measuredValue does not equal subject field")
        if subject_field == "deviceArchetype":
            forbidden_claims = [
                subject.get("manifestDigest"),
                subject.get("subjectManifestId"),
                record.get("recordDigest"),
                record.get("qualificationRecordId"),
            ]
            taxonomy_blobs = [measurement_blob]
            if isinstance(measurement.get("evidenceBindings"), list):
                for taxonomy_binding in measurement["evidenceBindings"]:
                    if not isinstance(taxonomy_binding, Mapping):
                        continue
                    taxonomy_blob = (
                        evidence_git.blob(
                            taxonomy_binding.get("path"),
                            f"{source_label}.taxonomyEvidence.path",
                            errors,
                        )
                        if evidence_git is not None
                        else None
                    )
                    taxonomy_blobs.append(taxonomy_blob)
            for forbidden in forbidden_claims:
                if not isinstance(forbidden, str):
                    continue
                encoded = forbidden.encode("utf-8")
                if any(
                    isinstance(candidate, bytes) and encoded in candidate
                    for candidate in taxonomy_blobs
                ):
                    errors.append(
                        f"{source_label}: taxonomy evidence consumes a later "
                        "Subject/QualificationRecord identity"
                    )
                    break

        collector = measurement.get("collector")
        if isinstance(collector, Mapping):
            collector_blob = (
                code_git.blob(collector.get("path"), f"{source_label}.collector.path", errors)
                if code_git is not None
                else None
            )
            _check_blob_hash(
                collector_blob,
                collector.get("blobSha256"),
                f"{source_label}.collector",
                errors,
            )
            tool_blob = (
                code_git.blob(
                    collector.get("toolManifestPath"),
                    f"{source_label}.collector.toolManifestPath",
                    errors,
                )
                if code_git is not None
                else None
            )
            _check_blob_hash(
                tool_blob,
                collector.get("toolManifestSha256"),
                f"{source_label}.collector.toolManifest",
                errors,
            )
            collector_matches: list[Mapping[str, Any]] = []
            if isinstance(mapping, Mapping):
                collector_matches = [
                    binding
                    for item in mapping.get("mappings", [])
                    if isinstance(item, Mapping)
                    for binding in item.get("targetBindings", [])
                    if isinstance(binding, Mapping)
                    and binding.get("path") == collector.get("path")
                    and binding.get("interfaceHash") == collector.get("interfaceHash")
                    and binding.get("symbolKind") in {"FUNCTION", "TEST"}
                ]
            if len(collector_matches) != 1:
                errors.append(
                    f"{source_label}.collector: path/interface resolves "
                    f"{len(collector_matches)} signed target bindings"
                )

        evidence_bindings = measurement.get("evidenceBindings")
        if not isinstance(evidence_bindings, list):
            evidence_bindings = []
        binding_order: list[bytes] = []
        observed_roles: set[str] = set()
        core_input_hashes: set[str] = set()
        role_counts: dict[str, int] = {}
        full_value_proof = False
        for binding_number, binding in enumerate(evidence_bindings):
            binding_label = f"{source_label}.evidenceBindings[{binding_number}]"
            if not isinstance(binding, Mapping):
                continue
            try:
                binding_order.append(
                    canonical_json_bytes(
                        [
                            binding.get("evidenceRole"),
                            binding.get("path"),
                            binding.get("sha256"),
                        ]
                    )
                )
            except (CanonicalizationError, TypeError, ValueError) as exc:
                errors.append(f"{binding_label}: invalid order key: {exc}")
            role = binding.get("evidenceRole")
            if isinstance(role, str):
                observed_roles.add(role)
                role_counts[role] = role_counts.get(role, 0) + 1
            binding_hash = binding.get("sha256")
            if isinstance(binding_hash, str):
                if isinstance(subject_field, str) and isinstance(role, str):
                    evidence_hash_owners.setdefault(binding_hash, set()).add(
                        (subject_field, role)
                    )
                if role == "HOST_INVENTORY_RECORD" and isinstance(
                    subject_field, str
                ):
                    inventory_binding_hashes.setdefault(subject_field, set()).add(
                        binding_hash
                    )
                if (
                    subject_field == "guestDriverAndWorkload"
                    and role == "WORKLOAD_RESULT"
                ):
                    workload_result_hashes.add(binding_hash)
            evidence_blob = (
                evidence_git.blob(binding.get("path"), f"{binding_label}.path", errors)
                if evidence_git is not None
                else None
            )
            _check_blob_hash(
                evidence_blob, binding.get("sha256"), binding_label, errors
            )
            if evidence_blob is not None and binding.get("byteLength") != len(evidence_blob):
                errors.append(f"{binding_label}.byteLength: raw evidence mismatch")
            evidence_document: Any | None = None
            schema_tuple = (
                binding.get("schemaRefOrNull"),
                binding.get("schemaSha256OrNull"),
                binding.get("valueProjectionOrNull"),
            )
            if any(value is None for value in schema_tuple) and not all(
                value is None for value in schema_tuple
            ):
                errors.append(f"{binding_label}: schema projection tuple is partial")
            if all(isinstance(value, str) for value in schema_tuple):
                schema_ref, schema_digest, pointer = schema_tuple
                schema_path = schema_ref.split("#", 1)[0]
                binding_schema_blob = _worktree_bytes(
                    root, schema_path, f"{binding_label}.schemaRef", errors
                )
                _check_blob_hash(
                    binding_schema_blob, schema_digest, f"{binding_label}.schema", errors
                )
                evidence_document = (
                    _load_json_bytes(evidence_blob, binding_label, errors)
                    if evidence_blob is not None
                    else None
                )
                if evidence_document is not None:
                    _validate_closed_json_schema_instance(
                        evidence_document, root, schema_ref, binding_label, errors
                    )
                    projected_value = _json_pointer_projection(
                        evidence_document, pointer, f"{binding_label}.valueProjection", errors
                    )
                    if projected_value == measured_value:
                        full_value_proof = True
            if role == "DEVICE_INVENTORY_RECORD" and isinstance(
                subject_field, str
            ):
                device_bindings_by_field.setdefault(subject_field, []).append(
                    binding
                )
                if isinstance(evidence_document, Mapping):
                    exact_device = {
                        "deviceUid": subject.get("deviceUid"),
                        "deviceRecordHash": subject.get("deviceRecordHash"),
                    }
                    for field, expected in exact_device.items():
                        if evidence_document.get(field) != expected:
                            errors.append(
                                f"{binding_label}.{field}: exact qualification "
                                "device mismatch"
                            )
                    if (
                        isinstance(current_inventory, Mapping)
                        and evidence_document.get("deviceRecordHash")
                        not in current_inventory.get("deviceRecordDigests", [])
                    ):
                        errors.append(
                            f"{binding_label}.deviceRecordHash: absent from "
                            "current HostSnapshot"
                        )
                    if subject_field == "pciIdentityMatch":
                        measured_identity = (
                            measured_value
                            if isinstance(measured_value, Mapping)
                            else {}
                        )
                        derived_identity = _derive_qualification_pci_identity(
                            evidence_document,
                            measured_identity.get("errataProfileId"),
                            label=binding_label,
                            errors=errors,
                        )
                        if derived_identity != measured_value:
                            errors.append(
                                f"{binding_label}: deterministic pciIdentityMatch "
                                "projection mismatch"
                            )
                        else:
                            full_value_proof = True
                    elif subject_field == "deviceTraits" and binding.get(
                        "valueProjectionOrNull"
                    ) != "/technicalTraits":
                        errors.append(
                            f"{binding_label}.valueProjectionOrNull: "
                            "deviceTraits requires /technicalTraits"
                        )
            if role == "QUALIFICATION_TAXONOMY_RECORD":
                pending_classifications.append(
                    (
                        binding,
                        measured_value,
                        measurement.get("observedAt"),
                        binding_label,
                    )
                )
            if role == "SCENARIO_EXECUTION_CORE_INPUT" and isinstance(
                binding.get("sha256"), str
            ):
                core_input_hashes.add(binding["sha256"])
        if binding_order != sorted(binding_order) or len(binding_order) != len(
            set(binding_order)
        ):
            errors.append(f"{source_label}.evidenceBindings: non-canonical/duplicate")
        if observed_roles != expected_evidence_roles:
            errors.append(
                f"{source_label}.evidenceBindings: roles {sorted(observed_roles)} "
                f"must exactly equal {sorted(expected_evidence_roles)}"
            )
        if subject_field in {"pciIdentityMatch", "deviceTraits"}:
            for exact_role in (
                "HOST_INVENTORY_RECORD",
                "DEVICE_INVENTORY_RECORD",
            ):
                if role_counts.get(exact_role) != 1:
                    errors.append(
                        f"{source_label}.evidenceBindings: expected exactly one "
                        f"{exact_role}"
                    )
        if (
            subject_field == "deviceArchetype"
            and role_counts.get("QUALIFICATION_TAXONOMY_RECORD") != 1
        ):
            errors.append(
                f"{source_label}.evidenceBindings: expected exactly one "
                "QUALIFICATION_TAXONOMY_RECORD"
            )
        if (
            subject_field == "kernelQemuFirmwareBackend"
            and role_counts.get("RUNTIME_BINARY", 0) < 3
        ):
            errors.append(
                f"{source_label}.evidenceBindings: runtime measurement requires "
                "at least three distinct RUNTIME_BINARY bindings for kernel, "
                "QEMU and firmware"
            )
        if subject_field == "caseExecution" and core_input_hashes != {measured_value}:
            errors.append(
                f"{source_label}.evidenceBindings: core input raw digest must equal "
                "measured scenarioExecutionCoreDigest"
            )
        elif subject_field != "caseExecution" and not full_value_proof:
            errors.append(
                f"{source_label}.evidenceBindings: at least one schema-validated "
                "raw projection must byte-equal the complete measuredValue"
            )
    expected_device_descriptor: Mapping[str, Any] | None = None
    identity_device_bindings = device_bindings_by_field.get("pciIdentityMatch", [])
    trait_device_bindings = device_bindings_by_field.get("deviceTraits", [])
    if len(identity_device_bindings) == 1 and len(trait_device_bindings) == 1:
        identity_binding = identity_device_bindings[0]
        trait_binding = trait_device_bindings[0]
        descriptor_fields = (
            "path",
            "sha256",
            "byteLength",
            "mediaType",
            "schemaRefOrNull",
            "schemaSha256OrNull",
        )
        if any(
            identity_binding.get(field) != trait_binding.get(field)
            for field in descriptor_fields
        ):
            errors.append(
                f"{label}.QualificationSubject: identity and traits must bind "
                "the same exact DeviceRecord"
            )
        expected_device_descriptor = {
            "path": identity_binding.get("path"),
            "sha256": identity_binding.get("sha256"),
            "byteLength": identity_binding.get("byteLength"),
            "mediaType": identity_binding.get("mediaType"),
            "schemaRef": identity_binding.get("schemaRefOrNull"),
            "schemaSha256": identity_binding.get("schemaSha256OrNull"),
            "recordDigest": subject.get("deviceRecordHash"),
        }
    else:
        errors.append(
            f"{label}.QualificationSubject: exact identity/traits DeviceRecord "
            "bindings are unavailable"
        )
    if not isinstance(_qualification_run, Mapping):
        if pending_classifications:
            errors.append(
                f"{label}.QualificationSubject: classification cannot be "
                "validated without QualificationRunManifest"
            )
    else:
        for taxonomy_binding, archetype, observed_at, binding_label in (
            pending_classifications
        ):
            _validate_device_classification_record(
                taxonomy_binding,
                expected_device_descriptor=expected_device_descriptor,
                measured_archetype=archetype,
                measurement_observed_at=observed_at,
                run=_qualification_run,
                subject=subject,
                record=record,
                code_git=code_git,
                evidence_git=evidence_git,
                root=root,
                mapping=mapping,
                trust=trust,
                label=f"{binding_label}.DeviceClassificationRecord",
                errors=errors,
            )

    if source_order != sorted(source_order) or len(source_order) != len(set(source_order)):
        errors.append(
            f"{label}.QualificationSubject.measurementSources: must be uniquely "
            "ordered by the complete source tuple"
        )
    for subject_field in source_specs:
        if subject_field == "caseExecution":
            continue
        if len(sources_by_field.get(subject_field, [])) != 1:
            errors.append(
                f"{label}.QualificationSubject.measurementSources: expected exactly "
                f"one {subject_field} source"
            )
    if set(measured_cores) != set(declared_cores) or len(measured_cores) != len(
        set(measured_cores)
    ):
        errors.append(
            f"{label}.QualificationSubject.measurementSources: caseExecution must "
            "exactly cover all execution cores"
        )
    for digest, owners in evidence_hash_owners.items():
        allowed_inventory_reuse = owners and all(
            role in {"HOST_INVENTORY_RECORD", "DEVICE_INVENTORY_RECORD"}
            and field in {"pciIdentityMatch", "deviceTraits"}
            for field, role in owners
        )
        if len(owners) > 1 and not allowed_inventory_reuse:
            errors.append(
                f"{label}.QualificationSubject.measurementSources: raw evidence "
                f"{digest} is reused across field/role owners {sorted(owners)!r}"
            )
    for inventory_field in ("pciIdentityMatch", "deviceTraits"):
        if not (
            inventory_raw_hashes
            & inventory_binding_hashes.get(inventory_field, set())
        ):
            errors.append(
                f"{label}.QualificationSubject.{inventory_field}: current "
                "HostSnapshot raw artifact is not its HOST_INVENTORY_RECORD binding"
            )

    workload_observation = subject.get("workloadObservation")
    if isinstance(workload_observation, Mapping):
        started = _parse_time(
            workload_observation.get("startedAt"),
            f"{label}.QualificationSubject.workloadObservation.startedAt",
            errors,
        )
        finished = _parse_time(
            workload_observation.get("finishedAt"),
            f"{label}.QualificationSubject.workloadObservation.finishedAt",
            errors,
        )
        observed_duration = workload_observation.get(
            "monotonicDurationNanoseconds"
        )
        run_workload_descriptor = (
            _qualification_run.get("workloadResult")
            if isinstance(_qualification_run, Mapping)
            else None
        )
        expected_duration = None
        if isinstance(run_workload_descriptor, Mapping):
            expected_duration = run_workload_descriptor.get(
                "monotonicDurationNanoseconds"
            )
        if observed_duration != expected_duration:
            errors.append(
                f"{label}.QualificationSubject.workloadObservation: duration must "
                f"equal workload result monotonic duration {expected_duration}"
            )
        minimum_duration = record.get("guestDriverAndWorkload", {}).get(
            "minimumDurationSeconds"
        ) if isinstance(record.get("guestDriverAndWorkload"), Mapping) else None
        if isinstance(minimum_duration, int):
            try:
                observed_duration_ns = int(observed_duration)
            except (TypeError, ValueError):
                errors.append(
                    f"{label}.QualificationSubject.workloadObservation: invalid "
                    "decimal nanosecond duration"
                )
            else:
                if observed_duration_ns < minimum_duration * 1_000_000_000:
                    errors.append(
                        f"{label}.QualificationSubject.workloadObservation: below "
                        f"workload minimum {minimum_duration} seconds"
                    )
        if isinstance(run_workload_descriptor, Mapping) and workload_observation.get(
            "startedAt"
        ) != run_workload_descriptor.get("startedAt"):
            errors.append(
                f"{label}.QualificationSubject.workloadObservation.startedAt: "
                "must equal parsed workload result"
            )
        if isinstance(run_workload_descriptor, Mapping) and workload_observation.get(
            "finishedAt"
        ) != run_workload_descriptor.get("finishedAt"):
            errors.append(
                f"{label}.QualificationSubject.workloadObservation.finishedAt: "
                "must equal parsed workload result"
            )
        if started is not None and finished is not None:
            if started >= finished:
                errors.append(
                    f"{label}.QualificationSubject.workloadObservation: invalid "
                    "monotonic/wall-clock duration"
                )
        workload_hash = workload_observation.get("workloadResultArtifactSha256")
        if isinstance(run_workload_descriptor, Mapping) and workload_hash != (
            run_workload_descriptor.get("sha256")
        ):
            errors.append(
                f"{label}.QualificationSubject.workloadObservation: raw result hash "
                "must equal QualificationRunManifest descriptor"
            )
        expected_workload_hashes = (
            {workload_hash} if isinstance(workload_hash, str) else set()
        )
        if workload_result_hashes != expected_workload_hashes:
            errors.append(
                f"{label}.QualificationSubject.workloadObservation: result hash "
                "must exactly equal the guest/workload Measurement WORKLOAD_RESULT "
                "binding"
            )
        workload_locations = (
            all_artifacts.get(workload_hash, [])
            if isinstance(workload_hash, str)
            else []
        )
        if len(workload_locations) != 1:
            errors.append(
                f"{label}.QualificationSubject.workloadObservation: workload result "
                "must resolve exactly one E4 artifact"
            )
        else:
            workload_artifact = workload_locations[0][0]
            if workload_artifact.get("evidenceRole") != "WORKLOAD_RESULT":
                errors.append(
                    f"{label}.QualificationSubject.workloadObservation: resolved "
                    "artifact lacks exclusive WORKLOAD_RESULT evidenceRole"
                )

    subject_time = subject_issued
    record_issued = _parse_time(record.get("issuedAt"), f"{label}.record.issuedAt", errors)
    index_created = [
        _parse_time(index.get("createdAt"), f"{label}.E4.createdAt", errors)
        for index in indexes
    ]
    index_finished = [
        _parse_time(index.get("runFinishedAt"), f"{label}.E4.runFinishedAt", errors)
        for index in indexes
    ]
    if subject_time is not None:
        if any(item is not None and item > subject_time for item in index_finished):
            errors.append(f"{label}: subject was signed before an execution core completed")
        if any(item is not None and subject_time > item for item in index_created):
            errors.append(f"{label}: subject must be signed before every E4 index")
    if record_issued is not None and any(
        item is not None and item > record_issued for item in index_created
    ):
        errors.append(f"{label}: QualificationRecord predates an E4 index")

    expected_e4_hashes = {
        subject.get("manifestDigest"),
        *(index.get("indexDigest") for index in indexes),
    }
    if set(record.get("e4EvidenceHashes", [])) != expected_e4_hashes:
        errors.append(
            f"{label}.record.e4EvidenceHashes: must exactly equal subject manifest "
            "digest plus all E4 index digests"
        )


def _validate_supported_catalog(
    catalog: Any,
    record_digests: set[str],
    active_selectors: Mapping[str, set[str]],
    index_issued_at: _datetime.datetime | None,
    trust: _TrustContext | None,
    label: str,
    errors: list[str],
) -> None:
    _exact_keys(catalog, SUPPORTED_CATALOG_FIELDS, label, errors)
    if not isinstance(catalog, Mapping):
        return
    if catalog.get("schemaVersion") != 1 or catalog.get("minimumReaderSchemaVersion") != 1:
        errors.append(f"{label}: unsupported schema/reader version")
    digests = _unique_strings(
        catalog.get("qualificationRecordDigests"), f"{label}.qualificationRecordDigests", errors
    )
    _require_canonical_set_order(
        catalog.get("qualificationRecordDigests"), f"{label}.qualificationRecordDigests", errors
    )
    for digest in digests:
        _is_digest(digest, f"{label}.qualificationRecordDigests", errors, nonzero=True)
    if set(digests) != record_digests:
        errors.append(
            f"{label}.qualificationRecordDigests: must exactly equal release records {sorted(record_digests)}"
        )
    sequence = catalog.get("catalogSequence")
    previous = catalog.get("previousCatalogDigest")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        errors.append(f"{label}.catalogSequence: expected positive integer")
    elif sequence == 1 and previous is not None:
        errors.append(f"{label}.previousCatalogDigest: genesis catalog requires null")
    elif sequence > 1 and previous is None:
        errors.append(f"{label}.previousCatalogDigest: required after sequence 1")
    if previous is not None:
        _is_digest(previous, f"{label}.previousCatalogDigest", errors)
    if catalog.get("revocationBehavior") != "DENY_NEW_AND_NEXT_POWER_ON":
        errors.append(f"{label}.revocationBehavior: unsafe or unknown behavior")
    deny_entries = catalog.get("denyAndRevocationEntries")
    if not isinstance(deny_entries, list):
        errors.append(f"{label}.denyAndRevocationEntries: expected array")
        deny_entries = []
    entry_ids: list[str] = []
    for index, entry in enumerate(deny_entries):
        entry_label = f"{label}.denyAndRevocationEntries[{index}]"
        _exact_keys(entry, DENY_ENTRY_FIELDS, entry_label, errors)
        if not isinstance(entry, Mapping):
            continue
        entry_ids.append(entry.get("entryId"))
        selector_kind = entry.get("selectorKind")
        if selector_kind not in active_selectors:
            errors.append(
                f"{entry_label}.selectorKind: unknown closed selector kind"
            )
        for field in ("selectorDigest", "evidenceHash"):
            _is_digest(entry.get(field), f"{entry_label}.{field}", errors, nonzero=True)
        expected_behavior = {
            "NORMAL": "DENY_NEW_AND_NEXT_POWER_ON",
            "CRITICAL": "DENY_NEW_AND_REQUIRE_CONTROLLED_STOP",
        }.get(entry.get("severity"))
        if expected_behavior is None:
            errors.append(f"{entry_label}.severity: expected NORMAL or CRITICAL")
        elif entry.get("revocationBehavior") != expected_behavior:
            errors.append(
                f"{entry_label}.revocationBehavior: severity {entry.get('severity')} requires {expected_behavior}"
            )
        effective = _parse_time(entry.get("effectiveAt"), f"{entry_label}.effectiveAt", errors)
        if (
            entry.get("selectorDigest")
            in active_selectors.get(selector_kind, set())
            and (effective is None or index_issued_at is None or effective <= index_issued_at)
        ):
            errors.append(f"{entry_label}: release includes an actively denied/revoked exact selector")
    if entry_ids != sorted(entry_ids) or len(entry_ids) != len(set(entry_ids)):
        errors.append(f"{label}.denyAndRevocationEntries: must be unique and sorted by entryId")
    issued = _parse_time(catalog.get("issuedAt"), f"{label}.issuedAt", errors)
    not_before = _parse_time(catalog.get("notBefore"), f"{label}.notBefore", errors)
    expires = _parse_time(catalog.get("expiresAt"), f"{label}.expiresAt", errors)
    if issued is not None and not_before is not None and issued > not_before:
        errors.append(f"{label}: issuedAt must not follow notBefore")
    if not_before is not None and expires is not None and not_before >= expires:
        errors.append(f"{label}: notBefore must precede expiresAt")
    if index_issued_at is not None and not_before is not None and expires is not None:
        if not (not_before <= index_issued_at < expires):
            errors.append(f"{label}: catalog is not valid at qualification index issuedAt")
    _verify_signed_envelope(
        catalog,
        digest_field="catalogDigest",
        signature_field="signature",
        signer_field="productReleaseSignerKeyId",
        signed_time_field="issuedAt",
        domain="QMAN-DIRECTPATH/SUPPORTED-CATALOG/V1",
        required_role="PRODUCT_RELEASE",
        trust=trust,
        label=label,
        errors=errors,
    )


def _external_anchor_bytes(
    value: Any,
    root: Path,
    code_git: _GitView | None,
    evidence_git: _GitView | None,
    label: str,
    errors: list[str],
) -> tuple[bytes | None, Mapping[str, Any] | None]:
    raw: bytes | None = None
    if isinstance(value, Mapping):
        try:
            raw = canonical_json_bytes(value)
        except (CanonicalizationError, TypeError, ValueError) as exc:
            errors.append(f"{label}: cannot canonicalize external object: {exc}")
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
    elif isinstance(value, (str, os.PathLike)):
        path = Path(value)
        try:
            path = path.resolve(strict=True)
            forbidden_roots = [root]
            forbidden_roots.extend(
                view.path
                for view in (code_git, evidence_git)
                if view is not None and view.path is not None
            )
            for forbidden_root in forbidden_roots:
                try:
                    path.relative_to(forbidden_root)
                except ValueError:
                    continue
                errors.append(
                    f"{label}: path is inside the integration-map/target/evidence "
                    "publisher checkout and is not an out-of-band authority"
                )
                return None, None
            raw = path.read_bytes()
        except OSError as exc:
            errors.append(f"{label}: cannot read external authority input: {exc}")
    elif value is None:
        errors.append(f"{label}: independently supplied external authority input is required")
    else:
        errors.append(f"{label}: unsupported external authority input type")
    if raw is None:
        return None, None
    document = _load_json_bytes(raw, label, errors)
    if not isinstance(document, Mapping):
        return raw, None
    try:
        canonical = canonical_json_bytes(document)
    except (CanonicalizationError, TypeError, ValueError) as exc:
        errors.append(f"{label}: cannot canonicalize: {exc}")
        return raw, document
    if raw != canonical:
        errors.append(f"{label}: external record must be exact CANONICAL-JSON-V1 bytes")
    return raw, document


def _positive_safe_integer(value: Any, label: str, errors: list[str]) -> int | None:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 1
        or value > SAFE_INTEGER
    ):
        errors.append(f"{label}: expected positive interoperable-safe integer")
        return None
    return value


def _validate_catalog_rollback_anchor(
    descriptor: Any,
    external_anchor: Any,
    catalog: Mapping[str, Any] | None,
    code_git: _GitView | None,
    evidence_git: _GitView | None,
    root: Path,
    trust: _TrustContext | None,
    errors: list[str],
    *,
    freshness_envelope: Any | None = None,
    verifier_nonce: str | None = None,
) -> Mapping[str, Any] | None:
    label = "catalogRollbackAnchor"
    mirror_blob = _typed_artifact_from_git(
        descriptor,
        evidence_git,
        root,
        label,
        errors,
        expected_schema_ref="contracts/directpath-catalog-rollback-anchor.schema.json",
    )
    external_bytes, anchor = _external_anchor_bytes(
        external_anchor,
        root,
        code_git,
        evidence_git,
        "trust bootstrap.external_catalog_anchor",
        errors,
    )
    if mirror_blob is not None and external_bytes is not None and mirror_blob != external_bytes:
        errors.append(
            f"{label}: evidence mirror bytes do not exactly equal the external authority record"
        )
    if isinstance(descriptor, Mapping) and external_bytes is not None:
        declared_hash = descriptor.get("sha256")
        actual_hash = sha256(external_bytes)
        if declared_hash != actual_hash:
            errors.append(
                f"{label}.sha256: external bytes hash {actual_hash}, declared {declared_hash}"
            )
    _exact_keys(anchor, CATALOG_ANCHOR_FIELDS, label, errors)
    if not isinstance(anchor, Mapping):
        return None
    expected_literals = {
        "schemaVersion": 1,
        "recordType": "DIRECTPATH_CATALOG_ROLLBACK_ANCHOR",
        "canonicalProfileId": "CANONICAL-JSON-V1",
        "recordState": "COMMITTED",
    }
    for field, expected in expected_literals.items():
        if anchor.get(field) != expected:
            errors.append(f"{label}.{field}: expected {expected!r}")
    anchor_version = _positive_safe_integer(
        anchor.get("anchorVersion"), f"{label}.anchorVersion", errors
    )
    resource_version = _positive_safe_integer(
        anchor.get("resourceVersion"), f"{label}.resourceVersion", errors
    )
    if (
        anchor_version is not None
        and resource_version is not None
        and anchor_version != resource_version
    ):
        errors.append(
            f"{label}: anchorVersion/resourceVersion is unreachable from the "
            "1/1 genesis with lockstep increments"
        )
    minimum_sequence = _positive_safe_integer(
        anchor.get("minimumCatalogSequence"),
        f"{label}.minimumCatalogSequence",
        errors,
    )
    _is_digest(anchor.get("acceptedCatalogDigest"), f"{label}.acceptedCatalogDigest", errors)
    updated_at = _parse_time(anchor.get("updatedAt"), f"{label}.updatedAt", errors)
    for field in ("catalogId", "authorityId"):
        if not isinstance(anchor.get(field), str) or not anchor.get(field):
            errors.append(f"{label}.{field}: expected non-empty ID")
    previous_digest = anchor.get("previousAnchorDigestOrNull")
    if previous_digest is not None:
        _is_digest(previous_digest, f"{label}.previousAnchorDigestOrNull", errors)
    anchor_projection = copy.deepcopy(dict(anchor))
    anchor_projection["anchorDigest"] = None
    anchor_projection["receipt"] = None
    computed_anchor_digest = _canonical_digest(
        anchor_projection, f"{label} digest projection", errors
    )
    if computed_anchor_digest is not None and anchor.get("anchorDigest") != computed_anchor_digest:
        errors.append(
            f"{label}.anchorDigest: declared {anchor.get('anchorDigest')}, "
            f"actual {computed_anchor_digest}"
        )
    cas = anchor.get("casPrecondition")
    _exact_keys(cas, CATALOG_ANCHOR_CAS_FIELDS, f"{label}.casPrecondition", errors)
    if isinstance(cas, Mapping) and anchor_version is not None and resource_version is not None:
        if anchor_version == 1:
            if resource_version != 1 or previous_digest is not None:
                errors.append(f"{label}: genesis anchor requires resourceVersion=1 and no predecessor")
            for field in CATALOG_ANCHOR_CAS_FIELDS:
                if cas.get(field) is not None:
                    errors.append(f"{label}.casPrecondition.{field}: genesis requires null")
        else:
            expected_anchor_version = _positive_safe_integer(
                cas.get("expectedAnchorVersionOrNull"),
                f"{label}.casPrecondition.expectedAnchorVersionOrNull",
                errors,
            )
            expected_resource_version = _positive_safe_integer(
                cas.get("expectedResourceVersionOrNull"),
                f"{label}.casPrecondition.expectedResourceVersionOrNull",
                errors,
            )
            expected_minimum = _positive_safe_integer(
                cas.get("expectedMinimumCatalogSequenceOrNull"),
                f"{label}.casPrecondition.expectedMinimumCatalogSequenceOrNull",
                errors,
            )
            for field in (
                "expectedAcceptedCatalogDigestOrNull",
                "expectedAnchorDigestOrNull",
            ):
                _is_digest(cas.get(field), f"{label}.casPrecondition.{field}", errors)
            if expected_anchor_version is not None and anchor_version != expected_anchor_version + 1:
                errors.append(f"{label}.anchorVersion: successor must increment CAS predecessor by one")
            if expected_resource_version is not None and resource_version != expected_resource_version + 1:
                errors.append(f"{label}.resourceVersion: successor must increment CAS predecessor by one")
            if previous_digest != cas.get("expectedAnchorDigestOrNull"):
                errors.append(f"{label}.previousAnchorDigestOrNull: does not equal CAS predecessor")
            if minimum_sequence is not None and expected_minimum is not None:
                if minimum_sequence < expected_minimum:
                    errors.append(f"{label}.minimumCatalogSequence: monotonic rollback detected")
                elif (
                    minimum_sequence == expected_minimum
                    and anchor.get("acceptedCatalogDigest")
                    != cas.get("expectedAcceptedCatalogDigestOrNull")
                ):
                    errors.append(f"{label}.acceptedCatalogDigest: same-sequence equivocation")
                elif minimum_sequence > expected_minimum:
                    if minimum_sequence != expected_minimum + 1:
                        errors.append(
                            f"{label}.minimumCatalogSequence: catalog chain cannot "
                            "skip an unverified predecessor"
                        )
                    if (
                        isinstance(catalog, Mapping)
                        and catalog.get("previousCatalogDigest")
                        != cas.get("expectedAcceptedCatalogDigestOrNull")
                    ):
                        errors.append(
                            f"{label}: candidate previousCatalogDigest does not "
                            "equal the CAS-accepted predecessor catalog"
                        )
    if isinstance(catalog, Mapping):
        if anchor.get("catalogId") != catalog.get("catalogId"):
            errors.append(f"{label}.catalogId: does not accept this SupportedCatalog")
        if minimum_sequence != catalog.get("catalogSequence"):
            errors.append(
                f"{label}.minimumCatalogSequence: must exactly equal candidate catalogSequence"
            )
        if anchor.get("acceptedCatalogDigest") != catalog.get("catalogDigest"):
            errors.append(f"{label}.acceptedCatalogDigest: does not accept candidate catalogDigest")
    receipt = anchor.get("receipt")
    _exact_keys(receipt, CATALOG_ANCHOR_RECEIPT_FIELDS, f"{label}.receipt", errors)
    if not isinstance(receipt, Mapping):
        if trust is not None:
            _validate_anchor_freshness_envelope(
                freshness_envelope,
                verifier_nonce,
                anchor_kind="SUPPORTED_CATALOG",
                anchor=anchor,
                anchor_raw=external_bytes,
                anchor_schema_ref="contracts/directpath-catalog-rollback-anchor.schema.json",
                subject_field="catalogId",
                root_set=trust.root_set,
                root=root,
                code_git=code_git,
                evidence_git=evidence_git,
                label="catalogRollbackAnchor.freshness",
                errors=errors,
            )
        return anchor
    if receipt.get("schemaVersion") != 1:
        errors.append(f"{label}.receipt.schemaVersion: expected 1")
    receipt_bindings = {
        "subjectAnchorDigest": anchor.get("anchorDigest"),
        "catalogId": anchor.get("catalogId"),
        "minimumCatalogSequence": anchor.get("minimumCatalogSequence"),
        "acceptedCatalogDigest": anchor.get("acceptedCatalogDigest"),
        "anchorVersion": anchor.get("anchorVersion"),
        "resourceVersion": anchor.get("resourceVersion"),
        "authorityId": anchor.get("authorityId"),
    }
    for field, expected in receipt_bindings.items():
        if receipt.get(field) != expected:
            errors.append(f"{label}.receipt.{field}: does not bind top-level anchor")
    if not isinstance(receipt.get("receiptId"), str) or not receipt.get("receiptId"):
        errors.append(f"{label}.receipt.receiptId: expected non-empty ID")
    receipt_time = _parse_time(receipt.get("issuedAt"), f"{label}.receipt.issuedAt", errors)
    if updated_at is not None and receipt_time is not None and receipt_time < updated_at:
        errors.append(f"{label}.receipt.issuedAt: precedes committed anchor update")
    receipt_projection = copy.deepcopy(dict(receipt))
    receipt_projection["receiptDigest"] = None
    receipt_projection["rootSignatures"] = []
    projection_bytes: bytes | None = None
    computed_receipt_digest: str | None = None
    try:
        projection_bytes = canonical_json_bytes(receipt_projection)
        computed_receipt_digest = sha256(projection_bytes)
        if receipt.get("receiptDigest") != computed_receipt_digest:
            errors.append(
                f"{label}.receipt.receiptDigest: declared {receipt.get('receiptDigest')}, "
                f"actual {computed_receipt_digest}"
            )
    except (CanonicalizationError, TypeError, ValueError) as exc:
        errors.append(f"{label}.receipt: cannot canonicalize signing projection: {exc}")
    signatures = receipt.get("rootSignatures")
    if not isinstance(signatures, list) or not signatures:
        errors.append(f"{label}.receipt.rootSignatures: expected non-empty quorum")
        signatures = []
    root_set = trust.root_set if trust is not None else None
    if not isinstance(root_set, Mapping):
        errors.append(f"{label}.receipt: independently authenticated root set is unavailable")
        return anchor
    if receipt.get("trustRootDigest") != root_set.get("rootSetDigest"):
        errors.append(f"{label}.receipt.trustRootDigest: does not bind authenticated root set")
    root_keys = {
        item.get("keyId"): item
        for item in root_set.get("keys", [])
        if isinstance(item, Mapping) and isinstance(item.get("keyId"), str)
    }
    policy = root_set.get("verificationPolicy")
    allowed_ids = (
        set(policy.get("allowedKeyIds", [])) if isinstance(policy, Mapping) else set()
    )
    threshold = policy.get("requiredSignatures") if isinstance(policy, Mapping) else None
    signature_ids: list[str] = []
    valid_principals: set[str] = set()
    for index, signature in enumerate(signatures):
        signature_label = f"{label}.receipt.rootSignatures[{index}]"
        _exact_keys(
            signature,
            CATALOG_ANCHOR_ROOT_SIGNATURE_FIELDS,
            signature_label,
            errors,
        )
        if not isinstance(signature, Mapping):
            continue
        key_id = signature.get("rootKeyId")
        signature_ids.append(key_id)
        if signature.get("algorithm") != "Ed25519":
            errors.append(f"{signature_label}.algorithm: expected Ed25519")
        signed_at = _parse_time(
            signature.get("signedAt"), f"{signature_label}.signedAt", errors
        )
        key = root_keys.get(key_id)
        if key is None or key_id not in allowed_ids:
            errors.append(f"{signature_label}.rootKeyId: is not an allowed authenticated root")
            continue
        not_before = _parse_time(
            key.get("notBefore"), f"{signature_label}.root.notBefore", errors
        )
        not_after = _parse_time(
            key.get("notAfter"), f"{signature_label}.root.notAfter", errors
        )
        if (
            signed_at is not None
            and not_before is not None
            and not_after is not None
            and not (not_before <= signed_at < not_after)
        ):
            errors.append(f"{signature_label}: root key was not valid at signed time")
        if receipt_time is not None and signed_at is not None and signed_at < receipt_time:
            errors.append(f"{signature_label}.signedAt: precedes receipt issuance")
        signature_preimage: bytes | None = None
        if computed_receipt_digest is not None:
            signature_subject = {
                "rootKeyId": key_id,
                "signedAt": signature.get("signedAt"),
                "receiptDigest": computed_receipt_digest,
            }
            try:
                signature_preimage = (
                    b"QMAN-DIRECTPATH/CATALOG-ROLLBACK-ANCHOR-RECEIPT/V1\x00"
                    + canonical_json_bytes(signature_subject)
                )
            except (CanonicalizationError, TypeError, ValueError) as exc:
                errors.append(
                    f"{signature_label}: cannot canonicalize signed subject: {exc}"
                )
        if signature_preimage is not None and _verify_ed25519(
            key.get("publicKeyBase64Url"),
            signature.get("signature"),
            signature_preimage,
            signature_label,
            errors,
        ):
            principal_id = key.get("principalId")
            if isinstance(principal_id, str):
                valid_principals.add(principal_id)
    if len(signature_ids) != len(set(signature_ids)):
        errors.append(f"{label}.receipt.rootSignatures: duplicate rootKeyId")
    if signature_ids != sorted(signature_ids, key=lambda item: canonical_json_bytes(item)):
        errors.append(f"{label}.receipt.rootSignatures: not canonically sorted by rootKeyId")
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1:
        errors.append(f"{label}.receipt: invalid authenticated root quorum policy")
    elif len(valid_principals) < threshold:
        errors.append(
            f"{label}.receipt.rootSignatures: {len(valid_principals)} valid "
            f"distinct root principals, {threshold} required"
        )
    _validate_anchor_freshness_envelope(
        freshness_envelope,
        verifier_nonce,
        anchor_kind="SUPPORTED_CATALOG",
        anchor=anchor,
        anchor_raw=external_bytes,
        anchor_schema_ref="contracts/directpath-catalog-rollback-anchor.schema.json",
        subject_field="catalogId",
        root_set=root_set,
        root=root,
        code_git=code_git,
        evidence_git=evidence_git,
        label="catalogRollbackAnchor.freshness",
        errors=errors,
    )
    return anchor


def _validate_qualification_release_legacy(
    descriptor: Any,
    code_git: _GitView | None,
    evidence_git: _GitView | None,
    root: Path,
    contract: Mapping[str, Any],
    trust: _TrustContext | None,
    errors: list[str],
    mapping: Mapping[str, Any] | None = None,
    external_catalog_anchor: Any | None = None,
) -> None:
    blob = _typed_artifact_from_git(
        descriptor,
        evidence_git,
        root,
        "qualificationEvidenceIndex",
        errors,
        expected_schema_ref="contracts/directpath-qualification-release-index.schema.json",
    )
    if blob is None:
        return
    index = _load_json_bytes(blob, "qualification release index", errors)
    _exact_keys(index, QUALIFICATION_INDEX_FIELDS, "qualification release index", errors)
    if not isinstance(index, Mapping):
        return
    if index.get("schemaVersion") != 1:
        errors.append("qualification release index.schemaVersion: expected 1")
    commit = _normal_commit(
        index.get("targetRepositoryCommit"),
        "qualification release index.targetRepositoryCommit",
        errors,
    )
    if code_git is not None and commit != code_git.commit:
        errors.append("qualification release index: target commit mismatch")
    issued_at = _parse_time(index.get("issuedAt"), "qualification release index.issuedAt", errors)
    policy_path = root / "contracts" / "compatibility-profile-policy.json"
    try:
        policy = _load_json_bytes(policy_path.read_bytes(), "compatibility profile policy", errors)
    except OSError as exc:
        errors.append(f"compatibility profile policy: cannot read: {exc}")
        policy = None
    platforms = policy.get("platforms", []) if isinstance(policy, Mapping) else []
    qualification_case_matrix = (
        policy.get("qualificationCaseMatrix") if isinstance(policy, Mapping) else None
    )
    known_cases = _contract_indexes(contract)["cases"]
    matrix_info: dict[str, Any] | None = None
    if not isinstance(qualification_case_matrix, Mapping) or not isinstance(policy, Mapping):
        errors.append(
            "qualification release index: compatibility policy lacks an independent closed qualificationCaseMatrix; self-declared record.caseIds cannot authorize QUALIFIED"
        )
    else:
        matrix_info = _validate_qualification_case_matrix(
            qualification_case_matrix,
            policy,
            known_cases,
            errors,
        )
    platform_by_id = {
        item.get("id"): item
        for item in platforms
        if isinstance(item, Mapping) and isinstance(item.get("id"), str)
    }
    platform_ids = _unique_strings(
        index.get("platformProfileIds"), "qualification release index.platformProfileIds", errors
    )
    _require_canonical_set_order(
        index.get("platformProfileIds"), "qualification release index.platformProfileIds", errors
    )
    if set(platform_ids) != set(platform_by_id):
        errors.append(
            "qualification release index.platformProfileIds: must exactly cover the six governed platform profiles"
        )
    e4_descriptors = index.get("e4EvidenceResults")
    if not isinstance(e4_descriptors, list) or not e4_descriptors:
        errors.append("qualification release index.e4EvidenceResults: expected non-empty array")
        e4_descriptors = []
    e4_hashes = {
        item.get("sha256")
        for item in e4_descriptors
        if isinstance(item, Mapping) and isinstance(item.get("sha256"), str)
    }
    record_descriptors = index.get("qualificationRecords")
    if not isinstance(record_descriptors, list) or not record_descriptors:
        errors.append("qualification release index.qualificationRecords: expected non-empty array")
        record_descriptors = []
    for field, records in (
        ("qualificationRecords", record_descriptors),
        ("e4EvidenceResults", e4_descriptors),
    ):
        ordering: list[bytes] = []
        for item in records:
            if isinstance(item, Mapping):
                try:
                    ordering.append(canonical_json_bytes([item.get("path"), item.get("sha256")]))
                except (CanonicalizationError, TypeError, ValueError):
                    pass
        if ordering != sorted(ordering) or len(ordering) != len(set(ordering)):
            errors.append(f"qualification release index.{field}: not unique/sorted by [path,sha256]")
    loaded_records: list[Mapping[str, Any]] = []
    for index_number, artifact in enumerate(record_descriptors):
        record_blob = _artifact_from_git(
            artifact,
            evidence_git,
            f"qualificationRecords[{index_number}]",
            errors,
        )
        if record_blob is None:
            continue
        record = _load_json_bytes(record_blob, f"qualificationRecords[{index_number}]", errors)
        if isinstance(record, Mapping):
            loaded_records.append(record)
    record_digests: set[str] = set()
    record_platform: dict[str, str] = {}
    record_cases: dict[str, set[str]] = {}
    runtime_coverage: dict[str, set[tuple[str, str]]] = {platform_id: set() for platform_id in platform_by_id}
    for index_number, record in enumerate(loaded_records):
        digest, platform_id, machine_pair = _validate_qualification_record(
            record,
            platform_by_id,
            policy,
            matrix_info,
            known_cases,
            e4_hashes,
            issued_at,
            trust,
            f"qualificationRecords[{index_number}]",
            errors,
        )
        if isinstance(digest, str):
            if digest in record_digests:
                errors.append(f"qualificationRecords[{index_number}]: duplicate recordDigest")
            record_digests.add(digest)
            if isinstance(platform_id, str):
                record_platform[digest] = platform_id
            record_cases[digest] = set(record.get("caseIds", []))
        if platform_id in runtime_coverage and machine_pair is not None:
            runtime_coverage[platform_id].add(machine_pair)
    for platform_id, platform in platform_by_id.items():
        expected_pairs = {
            (item.get("machine"), item.get("firmware"))
            for item in platform.get("machineFirmware", [])
            if isinstance(item, Mapping)
        }
        missing = expected_pairs - runtime_coverage.get(platform_id, set())
        if missing:
            errors.append(
                f"qualification release index: platform {platform_id} lacks record coverage for {sorted(missing)}"
            )
    catalog_blob = _artifact_from_git(
        index.get("supportedCatalog"),
        evidence_git,
        "supportedCatalog",
        errors,
    )
    catalog = _load_json_bytes(catalog_blob, "supportedCatalog", errors) if catalog_blob is not None else None
    active_selectors: dict[str, set[str]] = {
        "QUALIFICATION_RECORD": set(record_digests),
        "PCI_IDENTITY": set(),
        "PLATFORM_PROFILE": set(),
        "FIRMWARE": set(),
        "GUEST_DRIVER": set(),
        "WORKLOAD": set(),
    }
    for record in loaded_records:
        platform_hash = record.get("platformProfileHash")
        if isinstance(platform_hash, str):
            active_selectors["PLATFORM_PROFILE"].add(platform_hash)
        identity_digest = _canonical_digest(
            record.get("pciIdentityMatch"), "qualification PCI selector", errors
        )
        if identity_digest is not None:
            active_selectors["PCI_IDENTITY"].add(identity_digest)
        firmware = record.get("deviceFirmwareAndRom")
        if isinstance(firmware, Mapping):
            for field in ("deviceFirmwareDigest", "optionRomDigestOrNull", "vpdDigestOrNull", "settingsDigest"):
                if isinstance(firmware.get(field), str):
                    active_selectors["FIRMWARE"].add(firmware[field])
        workload = record.get("guestDriverAndWorkload")
        if isinstance(workload, Mapping):
            if isinstance(workload.get("guestDriverDigest"), str):
                active_selectors["GUEST_DRIVER"].add(workload["guestDriverDigest"])
            if isinstance(workload.get("workloadDefinitionDigest"), str):
                active_selectors["WORKLOAD"].add(workload["workloadDefinitionDigest"])
    _validate_supported_catalog(
        catalog,
        record_digests,
        active_selectors,
        issued_at,
        trust,
        "supportedCatalog",
        errors,
    )
    trust_policy = mapping.get("trustPolicy") if isinstance(mapping, Mapping) else None
    catalog_anchor_descriptor = (
        trust_policy.get("catalogRollbackAnchor")
        if isinstance(trust_policy, Mapping)
        else None
    )
    _validate_catalog_rollback_anchor(
        catalog_anchor_descriptor,
        external_catalog_anchor,
        catalog if isinstance(catalog, Mapping) else None,
        code_git,
        evidence_git,
        root,
        trust,
        errors,
    )
    qualification_signers = {
        record.get("qualificationSignerKeyId")
        for record in loaded_records
        if isinstance(record.get("qualificationSignerKeyId"), str)
    }
    product_release_signers = {
        index.get("signerKeyId"),
        catalog.get("productReleaseSignerKeyId") if isinstance(catalog, Mapping) else None,
    }
    signer_overlap = qualification_signers & product_release_signers
    if signer_overlap:
        errors.append(
            "qualification release index: Qualification Engineering and Product Release signer key IDs overlap "
            f"{sorted(signer_overlap)}"
        )
    covered_platforms: set[str] = set()
    covered_record_digests: set[str] = set()
    covered_cases_by_record: dict[str, set[str]] = {
        digest: set() for digest in record_digests
    }
    for index_number, item in enumerate(e4_descriptors):
        label = f"e4EvidenceResults[{index_number}]"
        _exact_keys(item, E4_RESULT_FIELDS, label, errors)
        if not isinstance(item, Mapping):
            continue
        for field in ("platformProfileIds", "caseIds", "qualificationRecordDigests"):
            values = _unique_strings(item.get(field), f"{label}.{field}", errors)
            _require_canonical_set_order(item.get(field), f"{label}.{field}", errors)
            if field == "platformProfileIds":
                unknown = sorted(set(values) - set(platform_by_id))
                if unknown:
                    errors.append(f"{label}.platformProfileIds: unknown profiles {unknown}")
                covered_platforms.update(values)
            elif field == "caseIds":
                unknown = sorted(set(values) - _contract_indexes(contract)["cases"])
                if unknown:
                    errors.append(f"{label}.caseIds: unknown Case IDs {unknown}")
            else:
                unknown = sorted(set(values) - record_digests)
                if unknown:
                    errors.append(f"{label}.qualificationRecordDigests: unknown records {unknown}")
                covered_record_digests.update(values)
        item_profiles = set(item.get("platformProfileIds", []))
        item_cases = set(item.get("caseIds", []))
        for record_digest in item.get("qualificationRecordDigests", []):
            if record_digest in record_platform and record_platform[record_digest] not in item_profiles:
                errors.append(
                    f"{label}: record {record_digest} platform {record_platform[record_digest]} is not bound"
                )
            if record_digest in covered_cases_by_record:
                unrelated_cases = item_cases - record_cases.get(record_digest, set())
                if unrelated_cases:
                    errors.append(
                        f"{label}: Case IDs {sorted(unrelated_cases)} are not required by record {record_digest}"
                    )
                covered_cases_by_record[record_digest].update(item_cases)
        evidence_blob = _artifact_from_git(
            {"path": item.get("path"), "sha256": item.get("sha256")},
            evidence_git,
            label,
            errors,
        )
        if evidence_blob is not None:
            evidence = _load_json_bytes(evidence_blob, label, errors)
            if not isinstance(evidence, Mapping) or evidence.get("definitionStatus") != "EXECUTED_PASS":
                errors.append(f"{label}: physical E4 evidence must be an EXECUTED_PASS scenario")
            else:
                applicability = evidence.get("applicability", {})
                if not isinstance(applicability, Mapping) or applicability.get("requiresPhysicalHardware") is not True:
                    errors.append(f"{label}: E4 scenario must require physical hardware")
                if evidence.get("caseId") not in set(item.get("caseIds", [])):
                    errors.append(f"{label}.caseIds: does not bind scenario Case")
                scenario_errors = _validate_scenario_document_core(
                    evidence,
                    contract,
                    root=root,
                    mapping_document=mapping,
                    _code_git_view=code_git,
                    _evidence_git_view=evidence_git,
                    _trust_context=trust,
                )
                errors.extend(f"{label}.scenario: {error}" for error in scenario_errors)
    if covered_platforms != set(platform_by_id):
        errors.append("qualification release index: E4 evidence does not cover every governed platform")
    if covered_record_digests != record_digests:
        errors.append("qualification release index: E4 evidence does not cover every qualification record")
    for record_digest, required_cases in record_cases.items():
        if covered_cases_by_record.get(record_digest, set()) != required_cases:
            errors.append(
                f"qualification release index: record {record_digest} E4 cases must exactly cover {sorted(required_cases)}"
            )
    _verify_signed_envelope(
        index,
        digest_field="indexDigest",
        signature_field="signature",
        signer_field="signerKeyId",
        signed_time_field="issuedAt",
        domain="QMAN-DIRECTPATH/QUALIFICATION-RELEASE-INDEX/V1",
        required_role="PRODUCT_RELEASE",
        trust=trust,
        label="qualification release index",
        errors=errors,
    )


def _validate_qualification_release(
    descriptor: Any,
    code_git: _GitView | None,
    evidence_git: _GitView | None,
    root: Path,
    contract: Mapping[str, Any],
    trust: _TrustContext | None,
    errors: list[str],
    mapping: Mapping[str, Any] | None = None,
    external_catalog_anchor: Any | None = None,
    catalog_anchor_freshness_envelope: Any | None = None,
    verifier_nonce: str | None = None,
) -> None:
    blob = _typed_artifact_from_git(
        descriptor,
        evidence_git,
        root,
        "qualificationEvidenceIndex",
        errors,
        expected_schema_ref="contracts/directpath-qualification-release-index.schema.json",
    )
    if blob is None:
        return
    index = _load_json_bytes(blob, "qualification release index", errors)
    _exact_keys(index, QUALIFICATION_INDEX_FIELDS, "qualification release index", errors)
    if not isinstance(index, Mapping):
        return
    if index.get("schemaVersion") != 1:
        errors.append("qualification release index.schemaVersion: expected 1")
    if index.get("canonicalProfileId") != "CANONICAL-JSON-V1":
        errors.append(
            "qualification release index.canonicalProfileId: expected CANONICAL-JSON-V1"
        )
    issued_at = _parse_time(
        index.get("issuedAt"), "qualification release index.issuedAt", errors
    )

    target_code = index.get("targetCodeRevision")
    _exact_keys(
        target_code,
        QUALIFICATION_TARGET_CODE_FIELDS,
        "qualification release index.targetCodeRevision",
        errors,
    )
    target_repository = (
        mapping.get("targetRepository") if isinstance(mapping, Mapping) else None
    )
    if isinstance(target_code, Mapping) and isinstance(target_repository, Mapping):
        expected_target = {
            "repositoryId": target_repository.get("repositoryId"),
            "objectFormat": target_repository.get("objectFormat"),
            "revision": code_git.commit if code_git is not None else None,
        }
        for field, expected in expected_target.items():
            if target_code.get(field) != expected:
                errors.append(
                    "qualification release index.targetCodeRevision."
                    f"{field}: expected exact target C value {expected!r}"
                )
    mapping_core = index.get("mappingCore")
    _exact_keys(
        mapping_core,
        QUALIFICATION_MAPPING_CORE_FIELDS,
        "qualification release index.mappingCore",
        errors,
    )
    if isinstance(mapping_core, Mapping) and isinstance(mapping, Mapping):
        expected_mapping_core = {
            "mappingCoreId": mapping.get("mappingCoreId"),
            "mappingCoreDigest": mapping.get("scenarioBindingDigest"),
        }
        for field, expected in expected_mapping_core.items():
            if mapping_core.get(field) != expected:
                errors.append(
                    f"qualification release index.mappingCore.{field}: "
                    f"expected mapping-core M value {expected!r}"
                )

    policy_path = root / "contracts" / "compatibility-profile-policy.json"
    try:
        policy = _load_json_bytes(
            policy_path.read_bytes(), "compatibility profile policy", errors
        )
    except OSError as exc:
        errors.append(f"compatibility profile policy: cannot read: {exc}")
        policy = None
    platforms = policy.get("platforms", []) if isinstance(policy, Mapping) else []
    platform_by_id = {
        item.get("id"): item
        for item in platforms
        if isinstance(item, Mapping) and isinstance(item.get("id"), str)
    }
    known_cases = _contract_indexes(contract)["cases"]
    matrix = (
        policy.get("qualificationCaseMatrix") if isinstance(policy, Mapping) else None
    )
    matrix_info: dict[str, Any] | None = None
    if isinstance(matrix, Mapping) and isinstance(policy, Mapping):
        matrix_info = _validate_qualification_case_matrix(
            matrix, policy, known_cases, errors
        )
    else:
        errors.append(
            "qualification release index: independent qualificationCaseMatrix is missing"
        )
    matrix_digest = matrix_info.get("digest") if isinstance(matrix_info, Mapping) else None
    if index.get("qualificationCaseMatrixSha256") != matrix_digest:
        errors.append(
            "qualification release index.qualificationCaseMatrixSha256: does not "
            f"equal active matrix {matrix_digest!r}"
        )
    platform_ids = _unique_strings(
        index.get("platformProfileIds"),
        "qualification release index.platformProfileIds",
        errors,
    )
    _require_canonical_set_order(
        index.get("platformProfileIds"),
        "qualification release index.platformProfileIds",
        errors,
    )
    if set(platform_ids) != set(platform_by_id):
        errors.append(
            "qualification release index.platformProfileIds: must exactly equal "
            "the governed platform-policy set"
        )

    case_registry = _load_case_contract_registry(contract, root, errors)
    e4_descriptors = index.get("e4CaseCompletionRecords")
    if not isinstance(e4_descriptors, list) or not e4_descriptors:
        errors.append(
            "qualification release index.e4CaseCompletionRecords: expected "
            "non-empty array"
        )
        e4_descriptors = []
    e4_order: list[bytes] = []
    e4_by_hash: dict[str, Mapping[str, Any]] = {}
    e4_completion_bundles: dict[str, Mapping[str, Any]] = {}
    e4_internal_hashes: set[str] = set()
    e4_completion_digests: set[str] = set()
    for number, artifact in enumerate(e4_descriptors):
        label = f"e4CaseCompletionRecords[{number}]"
        _exact_keys(artifact, E4_CASE_COMPLETION_FIELDS, label, errors)
        if not isinstance(artifact, Mapping):
            continue
        try:
            e4_order.append(
                canonical_json_bytes(
                    [
                        artifact.get("platformProfileId"),
                        artifact.get("exactQualificationKey"),
                        artifact.get("caseId"),
                        artifact.get("path"),
                        artifact.get("sha256"),
                        artifact.get("completionDigest"),
                    ]
                )
            )
        except (CanonicalizationError, TypeError, ValueError) as exc:
            errors.append(f"{label}: invalid canonical order key: {exc}")
        record_values = _unique_strings(
            artifact.get("qualificationRecordDigests"),
            f"{label}.qualificationRecordDigests",
            errors,
        )
        _require_canonical_set_order(
            artifact.get("qualificationRecordDigests"),
            f"{label}.qualificationRecordDigests",
            errors,
        )
        for digest in record_values:
            _is_digest(digest, f"{label}.qualificationRecordDigests", errors, nonzero=True)
        if artifact.get("platformProfileId") not in platform_by_id:
            errors.append(f"{label}.platformProfileId: unknown governed platform")
        if artifact.get("caseId") not in known_cases:
            errors.append(f"{label}.caseId: unknown closed Case")
        if artifact.get("evidenceGrade") != "E4-PHYSICAL-QUALIFICATION":
            errors.append(f"{label}.evidenceGrade: qualification requires E4")
        if artifact.get("targetRepositoryCommit") != (
            code_git.commit if code_git is not None else None
        ):
            errors.append(f"{label}.targetRepositoryCommit: target C mismatch")
        if isinstance(mapping, Mapping) and artifact.get("mappingCoreId") != mapping.get(
            "mappingCoreId"
        ):
            errors.append(f"{label}.mappingCoreId: mapping-core mismatch")
        raw_digest = artifact.get("sha256")
        completion_digest = artifact.get("completionDigest")
        if isinstance(raw_digest, str):
            if raw_digest in e4_by_hash:
                errors.append(f"{label}.sha256: duplicate E4 CaseCompletionRecord")
            e4_by_hash[raw_digest] = artifact
        if isinstance(completion_digest, str):
            if completion_digest in e4_completion_digests:
                errors.append(f"{label}.completionDigest: duplicate/reused completion")
            e4_completion_digests.add(completion_digest)
        bundle = _validate_case_completion_artifact(
            artifact,
            descriptor_fields=E4_CASE_COMPLETION_FIELDS,
            expected_platform_id=artifact.get("platformProfileId"),
            code_git=code_git,
            evidence_git=evidence_git,
            root=root,
            contract=contract,
            mapping=mapping,
            trust=trust,
            case_registry=case_registry,
            label=label,
            errors=errors,
        )
        if isinstance(bundle, Mapping) and isinstance(raw_digest, str):
            bundle = dict(bundle)
            bundle["ownerDomain"] = artifact.get("exactQualificationKey")
            e4_completion_bundles[raw_digest] = bundle
            for scenario_bundle in bundle.get("scenarioBundles", []):
                if not isinstance(scenario_bundle, Mapping):
                    continue
                scenario_index = scenario_bundle.get("index")
                subject = scenario_bundle.get("subject")
                if isinstance(scenario_index, Mapping) and isinstance(
                    scenario_index.get("indexDigest"), str
                ):
                    e4_internal_hashes.add(scenario_index["indexDigest"])
                if isinstance(subject, Mapping) and isinstance(
                    subject.get("manifestDigest"), str
                ):
                    e4_internal_hashes.add(subject["manifestDigest"])
    if e4_order != sorted(e4_order) or len(e4_order) != len(set(e4_order)):
        errors.append(
            "qualification release index.e4CaseCompletionRecords: must be unique "
            "and canonically sorted by "
            "[platformProfileId,exactQualificationKey,caseId,path,sha256,completionDigest]"
        )
    _validate_case_completion_set(
        list(e4_completion_bundles.values()),
        "qualification release index.e4CaseCompletionRecords",
        errors,
    )

    record_descriptors = index.get("qualificationRecords")
    if not isinstance(record_descriptors, list) or not record_descriptors:
        errors.append(
            "qualification release index.qualificationRecords: expected non-empty array"
        )
        record_descriptors = []
    record_order: list[bytes] = []
    records_by_digest: dict[str, Mapping[str, Any]] = {}
    record_platform: dict[str, str] = {}
    record_machine_pairs: dict[str, tuple[str, str]] = {}
    for number, artifact in enumerate(record_descriptors):
        label = f"qualificationRecords[{number}]"
        _exact_keys(artifact, QUALIFICATION_RECORD_ARTIFACT_FIELDS, label, errors)
        if not isinstance(artifact, Mapping):
            continue
        try:
            record_order.append(
                canonical_json_bytes(
                    [
                        artifact.get("qualificationRecordDigest"),
                        artifact.get("path"),
                        artifact.get("sha256"),
                    ]
                )
            )
        except (CanonicalizationError, TypeError, ValueError) as exc:
            errors.append(f"{label}: invalid canonical order key: {exc}")
        record_blob = _typed_artifact_from_git(
            artifact,
            evidence_git,
            root,
            label,
            errors,
            expected_schema_ref="contracts/directpath-qualification-record.schema.json",
            descriptor_fields=QUALIFICATION_RECORD_ARTIFACT_FIELDS,
        )
        record = (
            _load_json_bytes(record_blob, label, errors)
            if record_blob is not None
            else None
        )
        if not isinstance(record, Mapping):
            continue
        record_digest, platform_id, machine_pair = _validate_qualification_record(
            record,
            platform_by_id,
            policy,
            matrix_info,
            known_cases,
            e4_internal_hashes,
            issued_at,
            trust,
            label,
            errors,
        )
        if artifact.get("qualificationRecordDigest") != record_digest:
            errors.append(
                f"{label}.qualificationRecordDigest: does not equal parsed recordDigest"
            )
        if artifact.get("platformProfileId") != platform_id:
            errors.append(f"{label}.platformProfileId: does not equal record runtime")
        if isinstance(record_digest, str):
            if record_digest in records_by_digest:
                errors.append(f"{label}: duplicate qualification record digest")
            records_by_digest[record_digest] = record
            if isinstance(platform_id, str):
                record_platform[record_digest] = platform_id
            if machine_pair is not None:
                record_machine_pairs[record_digest] = machine_pair
    if record_order != sorted(record_order) or len(record_order) != len(set(record_order)):
        errors.append(
            "qualification release index.qualificationRecords: must be unique and "
            "canonically sorted by [qualificationRecordDigest,path,sha256]"
        )
    record_digests = set(records_by_digest)
    record_by_exact_key: dict[str, str] = {}
    for record_digest, record in records_by_digest.items():
        exact_key = record.get("exactQualificationKey")
        if not isinstance(exact_key, str):
            continue
        previous_record = record_by_exact_key.get(exact_key)
        if previous_record is not None and previous_record != record_digest:
            errors.append(
                "qualification release index.qualificationRecords: multiple active "
                f"records claim exactQualificationKey {exact_key!r}; an explicit "
                "supersession relation is required"
            )
        record_by_exact_key[exact_key] = record_digest
        record_cases = set(record.get("caseIds", []))
        for case_id in sorted(record_cases):
            generated_records = (
                case_registry.get("records", [])
                if isinstance(case_registry, Mapping)
                else []
            )
            generated_case = next(
                (
                    item
                    for item in generated_records
                    if isinstance(item, Mapping) and item.get("caseId") == case_id
                ),
                None,
            )
            generated_classification = (
                generated_case.get("classification")
                if isinstance(generated_case, Mapping)
                else None
            )
            dependencies = set(
                generated_classification.get("dependsOnCaseIds", [])
                if isinstance(generated_classification, Mapping)
                else []
            )
            missing_dependencies = dependencies - record_cases
            if missing_dependencies:
                errors.append(
                    f"qualification record {record_digest}: Case {case_id} lacks "
                    f"dependency closure {sorted(missing_dependencies)}"
                )
    runtime_coverage: dict[str, set[tuple[str, str]]] = {
        platform_id: set() for platform_id in platform_by_id
    }
    for digest, pair in record_machine_pairs.items():
        platform_id = record_platform.get(digest)
        if platform_id in runtime_coverage:
            runtime_coverage[platform_id].add(pair)
    for platform_id, platform in platform_by_id.items():
        required_pairs = {
            (item.get("machine"), item.get("firmware"))
            for item in platform.get("machineFirmware", [])
            if isinstance(item, Mapping)
        }
        missing_pairs = required_pairs - runtime_coverage.get(platform_id, set())
        if missing_pairs:
            errors.append(
                f"qualification release index: platform {platform_id} lacks "
                f"record coverage for {sorted(missing_pairs)}"
            )

    catalog_artifact = index.get("supportedCatalog")
    _exact_keys(
        catalog_artifact,
        QUALIFICATION_SUPPORTED_CATALOG_ARTIFACT_FIELDS,
        "supportedCatalog",
        errors,
    )
    catalog_blob = _typed_artifact_from_git(
        catalog_artifact,
        evidence_git,
        root,
        "supportedCatalog",
        errors,
        expected_schema_ref="contracts/directpath-supported-catalog.schema.json",
        descriptor_fields=QUALIFICATION_SUPPORTED_CATALOG_ARTIFACT_FIELDS,
    )
    catalog = (
        _load_json_bytes(catalog_blob, "supportedCatalog", errors)
        if catalog_blob is not None
        else None
    )
    active_selectors: dict[str, set[str]] = {
        "QUALIFICATION_RECORD": set(record_digests),
        "PCI_IDENTITY": set(),
        "PLATFORM_PROFILE": set(),
        "FIRMWARE": set(),
        "GUEST_DRIVER": set(),
        "WORKLOAD": set(),
    }
    for record in records_by_digest.values():
        platform_hash = record.get("platformProfileHash")
        if isinstance(platform_hash, str):
            active_selectors["PLATFORM_PROFILE"].add(platform_hash)
        identity_digest = _canonical_digest(
            record.get("pciIdentityMatch"), "qualification PCI selector", errors
        )
        if identity_digest is not None:
            active_selectors["PCI_IDENTITY"].add(identity_digest)
        firmware = record.get("deviceFirmwareAndRom")
        if isinstance(firmware, Mapping):
            for field in (
                "deviceFirmwareDigest",
                "optionRomDigestOrNull",
                "vpdDigestOrNull",
                "settingsDigest",
            ):
                if isinstance(firmware.get(field), str):
                    active_selectors["FIRMWARE"].add(firmware[field])
        workload = record.get("guestDriverAndWorkload")
        if isinstance(workload, Mapping):
            if isinstance(workload.get("guestDriverDigest"), str):
                active_selectors["GUEST_DRIVER"].add(workload["guestDriverDigest"])
            if isinstance(workload.get("workloadDefinitionDigest"), str):
                active_selectors["WORKLOAD"].add(
                    workload["workloadDefinitionDigest"]
                )
    _validate_supported_catalog(
        catalog,
        record_digests,
        active_selectors,
        issued_at,
        trust,
        "supportedCatalog",
        errors,
    )
    if isinstance(catalog, Mapping) and isinstance(catalog_artifact, Mapping):
        catalog_summary = {
            "catalogId": catalog.get("catalogId"),
            "catalogSequence": catalog.get("catalogSequence"),
            "catalogDigest": catalog.get("catalogDigest"),
        }
        for field, expected in catalog_summary.items():
            if catalog_artifact.get(field) != expected:
                errors.append(
                    f"supportedCatalog.{field}: descriptor does not equal parsed catalog"
                )

    coverage_items = index.get("qualificationCoverage")
    if not isinstance(coverage_items, list) or not coverage_items:
        errors.append(
            "qualification release index.qualificationCoverage: expected non-empty array"
        )
        coverage_items = []
    coverage_order: list[bytes] = []
    coverage_by_record: dict[str, Mapping[str, Any]] = {}
    reverse_e4_records: dict[str, set[str]] = {digest: set() for digest in e4_by_hash}
    completion_bundles_by_record: dict[str, list[Mapping[str, Any]]] = {}
    for number, coverage in enumerate(coverage_items):
        label = f"qualificationCoverage[{number}]"
        _exact_keys(coverage, QUALIFICATION_COVERAGE_FIELDS, label, errors)
        if not isinstance(coverage, Mapping):
            continue
        record_digest = coverage.get("qualificationRecordDigest")
        try:
            coverage_order.append(canonical_json_bytes(record_digest))
        except (CanonicalizationError, TypeError, ValueError) as exc:
            errors.append(f"{label}: invalid order key: {exc}")
        if not isinstance(record_digest, str) or record_digest not in records_by_digest:
            errors.append(f"{label}.qualificationRecordDigest: unknown release record")
            continue
        if record_digest in coverage_by_record:
            errors.append(f"{label}.qualificationRecordDigest: duplicate coverage entry")
        coverage_by_record[record_digest] = coverage
        expected_platform = record_platform.get(record_digest)
        if coverage.get("platformProfileId") != expected_platform:
            errors.append(f"{label}.platformProfileId: does not equal record platform")
        derived_cases = _unique_strings(
            coverage.get("derivedCaseIds"), f"{label}.derivedCaseIds", errors
        )
        _require_canonical_set_order(
            coverage.get("derivedCaseIds"), f"{label}.derivedCaseIds", errors
        )
        record = records_by_digest[record_digest]
        expected_cases = set(record.get("caseIds", []))
        if set(derived_cases) != expected_cases:
            errors.append(
                f"{label}.derivedCaseIds: must exactly equal parsed/matrix-derived "
                f"record Cases {sorted(expected_cases)}"
            )
        bindings = coverage.get("caseEvidenceBindings")
        if not isinstance(bindings, list) or not bindings:
            errors.append(f"{label}.caseEvidenceBindings: expected non-empty array")
            bindings = []
        binding_case_ids: list[str] = []
        binding_pairs: set[tuple[str, str]] = set()
        for binding_number, binding in enumerate(bindings):
            binding_label = f"{label}.caseEvidenceBindings[{binding_number}]"
            _exact_keys(binding, CASE_EVIDENCE_BINDING_FIELDS, binding_label, errors)
            if not isinstance(binding, Mapping):
                continue
            case_id = binding.get("caseId")
            evidence_hash = binding.get("e4CaseCompletionSha256")
            completion_digest = binding.get("e4CaseCompletionDigest")
            binding_case_ids.append(case_id)
            _is_digest(
                evidence_hash, f"{binding_label}.e4CaseCompletionSha256", errors
            )
            _is_digest(
                completion_digest,
                f"{binding_label}.e4CaseCompletionDigest",
                errors,
            )
            if isinstance(evidence_hash, str) and isinstance(completion_digest, str):
                pair = (evidence_hash, completion_digest)
                if pair in binding_pairs:
                    errors.append(f"{binding_label}: duplicate completion pair")
                binding_pairs.add(pair)
            e4 = e4_by_hash.get(evidence_hash)
            if not isinstance(e4, Mapping):
                errors.append(
                    f"{binding_label}: E4 CaseCompletionRecord hash does not resolve"
                )
                continue
            if e4.get("completionDigest") != completion_digest:
                errors.append(
                    f"{binding_label}.e4CaseCompletionDigest: descriptor mismatch"
                )
            if e4.get("caseId") != case_id:
                errors.append(
                    f"{binding_label}.caseId: does not equal completion descriptor Case"
                )
            if e4.get("platformProfileId") != expected_platform:
                errors.append(f"{binding_label}: completion descriptor platform mismatch")
            if e4.get("exactQualificationKey") != record.get("exactQualificationKey"):
                errors.append(f"{binding_label}: exactQualificationKey mismatch")
            if record_digest not in e4.get("qualificationRecordDigests", []):
                errors.append(
                    f"{binding_label}: completion descriptor lacks reverse record binding"
                )
            reverse_e4_records.setdefault(evidence_hash, set()).add(record_digest)
            completion_bundle = e4_completion_bundles.get(evidence_hash)
            if not isinstance(completion_bundle, Mapping):
                errors.append(f"{binding_label}: parsed CaseCompletionRecord is unavailable")
            else:
                completion_bundles_by_record.setdefault(record_digest, []).append(
                    completion_bundle
                )
                parsed_completion = completion_bundle.get("completion")
                record_backend_digest = _canonical_digest(
                    record.get("kernelQemuFirmwareBackend"),
                    f"{binding_label}.record.backendProfileDigest projection",
                    errors,
                )
                if isinstance(parsed_completion, Mapping):
                    completion_record_fields = {
                        "platformProfileId": expected_platform,
                        "platformProfileDigest": record.get("platformProfileHash"),
                        "backendProfileDigest": record_backend_digest,
                        "exactQualificationKey": record.get(
                            "exactQualificationKey"
                        ),
                    }
                    for field, expected in completion_record_fields.items():
                        if parsed_completion.get(field) != expected:
                            errors.append(
                                f"{binding_label}.{field}: signed CaseCompletion "
                                "does not equal QualificationRecord"
                            )
                record_issued = _parse_time(
                    record.get("issuedAt"), f"{binding_label}.record.issuedAt", errors
                )
                completion_at = completion_bundle.get("completedAt")
                if (
                    isinstance(record_issued, _datetime.datetime)
                    and isinstance(completion_at, _datetime.datetime)
                    and record_issued >= completion_at
                ):
                    errors.append(
                        f"{binding_label}: QualificationRecord must precede "
                        "CaseCompletionRecord"
                    )
                if (
                    isinstance(completion_at, _datetime.datetime)
                    and isinstance(issued_at, _datetime.datetime)
                    and completion_at >= issued_at
                ):
                    errors.append(
                        f"{binding_label}: CaseCompletionRecord must precede "
                        "qualification release index"
                    )
        if binding_case_ids != sorted(
            binding_case_ids, key=lambda value: canonical_json_bytes(value)
        ) or len(binding_case_ids) != len(set(binding_case_ids)):
            errors.append(
                f"{label}.caseEvidenceBindings: must be unique and sorted by caseId"
            )
        if set(binding_case_ids) != expected_cases:
            errors.append(
                f"{label}.caseEvidenceBindings: Case set must exactly equal "
                f"{sorted(expected_cases)}"
            )
        record_scenario_bundles = [
            scenario_bundle
            for completion_bundle in completion_bundles_by_record.get(record_digest, [])
            for scenario_bundle in completion_bundle.get("scenarioBundles", [])
            if isinstance(scenario_bundle, Mapping)
        ]
        backend_profile_digest = _canonical_digest(
            record.get("kernelQemuFirmwareBackend"),
            f"{label}.kernelQemuFirmwareBackend",
            errors,
        )
        for bundle_number, scenario_bundle in enumerate(record_scenario_bundles):
            scenario = scenario_bundle.get("scenario")
            scenario_label = f"{label}.scenarioBundles[{bundle_number}]"
            target_binding = (
                scenario.get("targetBinding") if isinstance(scenario, Mapping) else None
            )
            if not isinstance(target_binding, Mapping):
                errors.append(f"{scenario_label}: signed targetBinding is missing")
            else:
                if target_binding.get("platformProfileDigest") != record.get(
                    "platformProfileHash"
                ):
                    errors.append(
                        f"{scenario_label}.platformProfileDigest: QualificationRecord mismatch"
                    )
                if target_binding.get("backendProfileDigest") != backend_profile_digest:
                    errors.append(
                        f"{scenario_label}.backendProfileDigest: QualificationRecord mismatch"
                    )
            result = (
                scenario.get("executionResult") if isinstance(scenario, Mapping) else None
            )
            instances = (
                result.get("artifactInstances", [])
                if isinstance(result, Mapping)
                else []
            )
            for instance_number, instance in enumerate(instances):
                correlation = (
                    instance.get("correlation") if isinstance(instance, Mapping) else None
                )
                bindings_map = (
                    _subject_binding_map(
                        correlation.get("subjectBindings"),
                        f"{scenario_label}.artifactInstances[{instance_number}]"
                        ".correlation.subjectBindings",
                        errors,
                    )
                    if isinstance(correlation, Mapping)
                    else {}
                )
                if bindings_map.get("exactQualificationKey") != record.get(
                    "exactQualificationKey"
                ):
                    errors.append(
                        f"{scenario_label}.artifactInstances[{instance_number}]: "
                        "exactQualificationKey binding mismatch"
                    )
        _validate_qualification_subject_manifest(
            record,
            record_scenario_bundles,
            case_registry,
            trust,
            root,
            code_git,
            evidence_git,
            mapping,
            label,
            errors,
        )
    if coverage_order != sorted(coverage_order) or len(coverage_order) != len(
        set(coverage_order)
    ):
        errors.append(
            "qualification release index.qualificationCoverage: must be unique and "
            "canonically sorted by qualificationRecordDigest"
        )
    if set(coverage_by_record) != record_digests:
        errors.append(
            "qualification release index.qualificationCoverage: record set does not "
            "exactly equal qualificationRecords"
        )
    for evidence_hash, artifact in e4_by_hash.items():
        declared_records = set(artifact.get("qualificationRecordDigests", []))
        reverse_records = reverse_e4_records.get(evidence_hash, set())
        if declared_records != reverse_records:
            errors.append(
                f"e4CaseCompletionRecords[{evidence_hash}]: qualificationRecordDigests "
                f"must exactly equal reverse coverage references {sorted(reverse_records)}"
            )
        unknown_records = declared_records - record_digests
        if unknown_records:
            errors.append(
                f"e4CaseCompletionRecords[{evidence_hash}]: unknown record digests "
                f"{sorted(unknown_records)}"
            )
        bound_records = [
            records_by_digest[digest]
            for digest in declared_records
            if digest in records_by_digest
        ]
        exact_keys = {
            record.get("exactQualificationKey")
            for record in bound_records
            if isinstance(record.get("exactQualificationKey"), str)
        }
        if len(exact_keys) != 1:
            errors.append(
                f"e4CaseCompletionRecords[{evidence_hash}]: one completion may bind only "
                "one exactQualificationKey"
            )
            continue
        exact_key = next(iter(exact_keys))
        if artifact.get("exactQualificationKey") != exact_key:
            errors.append(
                f"e4CaseCompletionRecords[{evidence_hash}].exactQualificationKey: "
                "does not equal all reverse-bound records"
            )
        platforms_for_records = {
            record_platform.get(digest) for digest in declared_records
        }
        if platforms_for_records != {artifact.get("platformProfileId")}:
            errors.append(
                f"e4CaseCompletionRecords[{evidence_hash}].platformProfileId: "
                "does not equal all reverse-bound records"
            )

    anchor_binding = index.get("catalogRollbackAnchor")
    _exact_keys(
        anchor_binding,
        QUALIFICATION_ANCHOR_BINDING_FIELDS,
        "qualification release index.catalogRollbackAnchor",
        errors,
    )
    snapshot_descriptor = (
        anchor_binding.get("snapshot")
        if isinstance(anchor_binding, Mapping)
        else None
    )
    trust_policy = mapping.get("trustPolicy") if isinstance(mapping, Mapping) else None
    map_anchor_descriptor = (
        trust_policy.get("catalogRollbackAnchor")
        if isinstance(trust_policy, Mapping)
        else None
    )
    if map_anchor_descriptor != snapshot_descriptor:
        errors.append(
            "qualification release index.catalogRollbackAnchor.snapshot: must "
            "exactly equal integration-map trustPolicy descriptor"
        )
    external_anchor_document = _validate_catalog_rollback_anchor(
        snapshot_descriptor,
        external_catalog_anchor,
        catalog if isinstance(catalog, Mapping) else None,
        code_git,
        evidence_git,
        root,
        trust,
        errors,
        freshness_envelope=catalog_anchor_freshness_envelope,
        verifier_nonce=verifier_nonce,
    )
    if isinstance(anchor_binding, Mapping):
        if anchor_binding.get("recordState") != "COMMITTED":
            errors.append(
                "qualification release index.catalogRollbackAnchor.recordState: "
                "expected COMMITTED"
            )
        top_fields = (
            "catalogId",
            "minimumCatalogSequence",
            "acceptedCatalogDigest",
            "anchorVersion",
            "resourceVersion",
            "authorityId",
            "anchorDigest",
        )
        if isinstance(external_anchor_document, Mapping):
            for field in top_fields:
                if anchor_binding.get(field) != external_anchor_document.get(field):
                    errors.append(
                        "qualification release index.catalogRollbackAnchor."
                        f"{field}: does not mirror external committed anchor"
                    )
        receipt_binding = anchor_binding.get("receipt")
        _exact_keys(
            receipt_binding,
            QUALIFICATION_ANCHOR_RECEIPT_FIELDS,
            "qualification release index.catalogRollbackAnchor.receipt",
            errors,
        )
        external_receipt = (
            external_anchor_document.get("receipt")
            if isinstance(external_anchor_document, Mapping)
            else None
        )
        if isinstance(receipt_binding, Mapping) and isinstance(external_receipt, Mapping):
            for field in QUALIFICATION_ANCHOR_RECEIPT_FIELDS:
                if receipt_binding.get(field) != external_receipt.get(field):
                    errors.append(
                        "qualification release index.catalogRollbackAnchor.receipt."
                        f"{field}: does not mirror external receipt"
                    )
            receipt_issued = _parse_time(
                receipt_binding.get("issuedAt"),
                "qualification release index.catalogRollbackAnchor.receipt.issuedAt",
                errors,
            )
            if (
                receipt_issued is not None
                and issued_at is not None
                and receipt_issued > issued_at
            ):
                errors.append(
                    "qualification release index.catalogRollbackAnchor.receipt: "
                    "postdates the signed qualification index"
                )

    qualification_signers = {
        record.get("qualificationSignerKeyId")
        for record in records_by_digest.values()
        if isinstance(record.get("qualificationSignerKeyId"), str)
    }
    product_release_signers = {
        index.get("signerKeyId"),
        catalog.get("productReleaseSignerKeyId")
        if isinstance(catalog, Mapping)
        else None,
    }
    overlap = qualification_signers & product_release_signers
    if overlap:
        errors.append(
            "qualification release index: Qualification Engineering and Product "
            f"Release signer key IDs overlap {sorted(overlap)}"
        )
    if trust is not None:
        qualification_keys = [
            trust.keys[key_id]
            for key_id in qualification_signers
            if key_id in trust.keys
        ]
        product_keys = [
            trust.keys[key_id]
            for key_id in product_release_signers
            if key_id in trust.keys
        ]
        qualification_principals = {
            key.get("principalId")
            for key in qualification_keys
            if isinstance(key.get("principalId"), str)
        }
        product_principals = {
            key.get("principalId")
            for key in product_keys
            if isinstance(key.get("principalId"), str)
        }
        principal_overlap = qualification_principals & product_principals
        if principal_overlap:
            errors.append(
                "qualification release index: Qualification Engineering and "
                f"Product Release principalIds overlap {sorted(principal_overlap)}"
            )
        qualification_material = {
            key.get("publicKeyBase64Url")
            for key in qualification_keys
            if isinstance(key.get("publicKeyBase64Url"), str)
        }
        product_material = {
            key.get("publicKeyBase64Url")
            for key in product_keys
            if isinstance(key.get("publicKeyBase64Url"), str)
        }
        material_overlap = qualification_material & product_material
        if material_overlap:
            errors.append(
                "qualification release index: Qualification Engineering and "
                "Product Release reuse Ed25519 key material"
            )
    _verify_signed_envelope(
        index,
        digest_field="indexDigest",
        signature_field="signature",
        signer_field="signerKeyId",
        signed_time_field="issuedAt",
        domain="QMAN-DIRECTPATH/QUALIFICATION-RELEASE-INDEX/V1",
        required_role="PRODUCT_RELEASE",
        trust=trust,
        label="qualification release index",
        errors=errors,
    )


def _validate_canonical_profiles(contract: Mapping[str, Any], root: Path, errors: list[str]) -> None:
    profiles = {
        item.get("id"): item
        for item in contract.get("canonicalizationContract", {}).get("profiles", [])
        if isinstance(item, Mapping)
    }
    canonical_profile = profiles.get("CANONICAL-JSON-V1")
    if not isinstance(canonical_profile, Mapping):
        errors.append("portable contract: CANONICAL-JSON-V1 profile is missing")
    else:
        for vector in canonical_profile.get("goldenVectors", []):
            if not isinstance(vector, Mapping):
                errors.append("CANONICAL-JSON-V1 golden vector: expected object")
                continue
            semantic = copy.deepcopy(vector.get("semanticInput"))
            if not isinstance(semantic, Mapping):
                errors.append(f"canonical vector {vector.get('id')}: semanticInput is not object")
                continue
            for field in vector.get("schemaSetFields", []):
                value = semantic.get(field)
                if not isinstance(value, list):
                    errors.append(f"canonical vector {vector.get('id')}: set field {field} is not array")
                    continue
                unique = {canonical_json_bytes(item): item for item in value}
                semantic[field] = [unique[key] for key in sorted(unique)]
            try:
                encoded = canonical_json_bytes(semantic)
            except (CanonicalizationError, TypeError, ValueError) as exc:
                errors.append(f"canonical vector {vector.get('id')}: {exc}")
                continue
            if encoded.decode("utf-8") != vector.get("canonicalUtf8"):
                errors.append(f"canonical vector {vector.get('id')}: canonical UTF-8 mismatch")
            if sha256(encoded) != vector.get("sha256"):
                errors.append(f"canonical vector {vector.get('id')}: digest mismatch")
    timestamp_profile = profiles.get("TIMESTAMP-UTC-US-V1")
    timestamp_pattern = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
    if not isinstance(timestamp_profile, Mapping):
        errors.append("portable contract: TIMESTAMP-UTC-US-V1 profile is missing")
    else:
        for vector in timestamp_profile.get("goldenVectors", []):
            if not isinstance(vector, Mapping):
                continue
            accepted = vector.get("accepted")
            if accepted is not None and (
                not isinstance(accepted, str) or timestamp_pattern.fullmatch(accepted) is None
            ):
                errors.append(f"timestamp golden vector: accepted value is rejected {accepted!r}")
            for rejected in vector.get("rejected", []):
                if isinstance(rejected, str) and timestamp_pattern.fullmatch(rejected) is not None:
                    errors.append(f"timestamp golden vector: rejected value is accepted {rejected!r}")
    identity_path = root / "contracts" / "directpath-identity-v1.schema.json"
    try:
        identity_schema = _load_json_bytes(identity_path.read_bytes(), "IDENTITY-V1 schema", errors)
    except OSError as exc:
        errors.append(f"IDENTITY-V1 schema: cannot read: {exc}")
        identity_schema = None
    if isinstance(identity_schema, Mapping):
        for vector in identity_schema.get("x-qmanGoldenVectors", []):
            if not isinstance(vector, Mapping):
                continue
            canonical_text = vector.get("canonicalUtf8")
            if not isinstance(canonical_text, str):
                errors.append(f"identity vector {vector.get('id')}: canonicalUtf8 missing")
                continue
            document = _load_json_bytes(canonical_text.encode("utf-8"), f"identity vector {vector.get('id')}", errors)
            if document is None:
                continue
            try:
                encoded = canonical_json_bytes(document)
            except (CanonicalizationError, TypeError, ValueError) as exc:
                errors.append(f"identity vector {vector.get('id')}: {exc}")
                continue
            if encoded.decode("utf-8") != canonical_text or sha256(encoded) != vector.get("sha256"):
                errors.append(f"identity vector {vector.get('id')}: bytes/digest mismatch")


def _validate_state_machine_contract(contract: Mapping[str, Any], errors: list[str]) -> None:
    machine_ids: set[str] = set()
    transition_ids: set[str] = set()
    for machine_index, machine in enumerate(contract.get("stateMachines", [])):
        label = f"portable contract.stateMachines[{machine_index}]"
        if not isinstance(machine, Mapping):
            errors.append(f"{label}: expected object")
            continue
        machine_id = machine.get("id")
        if machine_id in machine_ids:
            errors.append(f"{label}.id: duplicate FSM ID {machine_id!r}")
        if isinstance(machine_id, str):
            machine_ids.add(machine_id)
        states = machine.get("states")
        if not isinstance(states, list) or not states or len(states) != len(set(states)):
            errors.append(f"{label}.states: expected non-empty unique ordered states")
            states = []
        state_set = set(states)
        terminals = set(machine.get("terminalStates", []))
        if not terminals.issubset(state_set):
            errors.append(f"{label}.terminalStates: contains unknown states")
        quiescent = set(machine.get("quiescentStates", []))
        if not quiescent.issubset(state_set):
            errors.append(f"{label}.quiescentStates: contains unknown states")
        pseudo = machine.get("pseudoStateExpansions", {})
        if not isinstance(pseudo, Mapping):
            errors.append(f"{label}.pseudoStateExpansions: expected object")
            pseudo = {}
        for pseudo_name, expansion in pseudo.items():
            if not isinstance(pseudo_name, str) or not pseudo_name.startswith("ANY_"):
                errors.append(f"{label}.pseudoStateExpansions: invalid pseudo-state name {pseudo_name!r}")
            if not isinstance(expansion, list) or not expansion:
                errors.append(f"{label}.pseudoStateExpansions.{pseudo_name}: expected non-empty array")
                continue
            if expansion != [state for state in states if state in set(expansion)]:
                errors.append(
                    f"{label}.pseudoStateExpansions.{pseudo_name}: must be unique and in canonical FSM state order"
                )
            if not set(expansion).issubset(state_set):
                errors.append(f"{label}.pseudoStateExpansions.{pseudo_name}: unknown state")
            if set(expansion) & terminals:
                errors.append(f"{label}.pseudoStateExpansions.{pseudo_name}: terminal states cannot have outgoing transitions")
        for transition_index, transition in enumerate(machine.get("transitions", [])):
            transition_label = f"{label}.transitions[{transition_index}]"
            if not isinstance(transition, Mapping):
                errors.append(f"{transition_label}: expected object")
                continue
            transition_id = transition.get("id")
            if transition_id in transition_ids:
                errors.append(f"{transition_label}.id: duplicate transition ID")
            if isinstance(transition_id, str):
                transition_ids.add(transition_id)
            source = transition.get("from")
            target = transition.get("to")
            if target not in state_set:
                errors.append(f"{transition_label}.to: unknown concrete state {target!r}")
            if isinstance(source, str) and source.startswith("ANY_"):
                expansion = pseudo.get(source)
                if expansion is None:
                    errors.append(f"{transition_label}.from: undeclared pseudo-state {source}")
                if transition.get("fromStateExpansion") != expansion:
                    errors.append(
                        f"{transition_label}.fromStateExpansion: must equal exact pseudoStateExpansions entry"
                    )
            else:
                if source not in state_set:
                    errors.append(f"{transition_label}.from: unknown concrete state {source!r}")
                if source in terminals:
                    errors.append(f"{transition_label}.from: terminal state cannot have outgoing transition")
                if "fromStateExpansion" in transition:
                    errors.append(f"{transition_label}.fromStateExpansion: forbidden for concrete from-state")


def _wire_schema_shape(
    root: Path,
    schema_ref: str,
    label: str,
    errors: list[str],
    seen: set[str] | None = None,
) -> tuple[bool, set[str], set[str]] | None:
    """Resolve a local entity schema's closed top-level shape through $ref/allOf."""

    visited = set() if seen is None else seen
    if schema_ref in visited:
        errors.append(f"{label}: cyclic top-level schema reference {schema_ref!r}")
        return None
    visited.add(schema_ref)
    node = _load_worktree_schema_ref(root, schema_ref, label, errors)
    if not isinstance(node, Mapping):
        return None
    path_text = schema_ref.partition("#")[0]
    properties = set(node.get("properties", {}))
    required = set(node.get("required", []))
    closed_sets: list[set[str]] = []
    if node.get("additionalProperties") is False:
        closed_sets.append(set(properties))

    references: list[str] = []
    direct_ref = node.get("$ref")
    if isinstance(direct_ref, str):
        references.append(direct_ref)
    all_of = node.get("allOf")
    if isinstance(all_of, list):
        for index, branch in enumerate(all_of):
            if not isinstance(branch, Mapping):
                errors.append(f"{label}.allOf[{index}]: expected object schema")
                continue
            branch_ref = branch.get("$ref")
            if isinstance(branch_ref, str):
                references.append(branch_ref)
            branch_properties = set(branch.get("properties", {}))
            properties.update(branch_properties)
            required.update(branch.get("required", []))
            if branch.get("additionalProperties") is False:
                closed_sets.append(branch_properties)
    for reference in references:
        if reference.startswith("#"):
            resolved_ref = path_text + reference
        else:
            ref_path, separator, fragment = reference.partition("#")
            base = PurePosixPath(path_text).parent
            combined = (base / PurePosixPath(ref_path)).as_posix()
            safe = _safe_relative_path(combined, f"{label}.$ref", errors)
            if safe is None:
                continue
            resolved_ref = safe + (("#" + fragment) if separator else "")
        shape = _wire_schema_shape(root, resolved_ref, label, errors, set(visited))
        if shape is None:
            continue
        referenced_closed, referenced_required, referenced_properties = shape
        properties.update(referenced_properties)
        required.update(referenced_required)
        if referenced_closed:
            closed_sets.append(referenced_properties)
    if closed_sets and any(not properties.issubset(fields) for fields in closed_sets):
        errors.append(
            f"{label}: allOf adds fields outside a branch closed by additionalProperties=false"
        )
    return bool(closed_sets), required, properties


def _validate_wire_schema_closure(contract: Mapping[str, Any], root: Path, errors: list[str]) -> None:
    normative_sources = {
        item
        for item in contract.get("normativeSources", [])
        if isinstance(item, str)
    }
    for entity in contract.get("dataEntities", []):
        if not isinstance(entity, Mapping) or not isinstance(entity.get("wireSchema"), str):
            continue
        label = f"{entity.get('id')} wire schema"
        schema_path = entity["wireSchema"].partition("#")[0]
        if schema_path not in normative_sources:
            errors.append(
                f"{label}: base schema path is absent from normativeSources"
            )
        shape = _wire_schema_shape(root, entity["wireSchema"], label, errors)
        if shape is None:
            continue
        closed, required, properties = shape
        if not closed:
            errors.append(f"{label}: top-level schema must be closed")
        entity_required = set(entity.get("requiredFields", [])) | set(entity.get("key", []))
        if required != entity_required or properties != entity_required:
            errors.append(
                f"{label}: schema fields do not exactly equal entity key∪requiredFields"
            )
    schema_cache: dict[str, Any] = {}
    for subject in contract.get("canonicalizationContract", {}).get("hashSubjects", []):
        if not isinstance(subject, Mapping):
            errors.append("portable hashSubjects: expected object")
            continue
        reference = subject.get("schemaRef")
        label = f"hash subject {subject.get('subject')}"
        if not isinstance(reference, str) or not reference:
            errors.append(f"{label}: schemaRef is required")
            continue
        path_text, separator, fragment = reference.partition("#")
        if path_text not in normative_sources:
            errors.append(
                f"{label}: base schema path is absent from normativeSources"
            )
        if path_text not in schema_cache:
            blob = _worktree_bytes(root, path_text, f"{label}.schemaRef", errors)
            schema_cache[path_text] = (
                _load_json_bytes(blob, f"{label}.schemaRef", errors) if blob is not None else None
            )
        node = schema_cache[path_text]
        if separator and fragment:
            if not fragment.startswith("/"):
                errors.append(f"{label}: unsupported non-JSON-pointer schema fragment")
                continue
            for token in fragment.lstrip("/").split("/"):
                token = token.replace("~1", "/").replace("~0", "~")
                if not isinstance(node, Mapping) or token not in node:
                    errors.append(f"{label}: unresolved schemaRef fragment {fragment}")
                    node = None
                    break
                node = node[token]
        if not isinstance(node, Mapping):
            continue
        closed = node.get("additionalProperties") is False
        if not closed and isinstance(node.get("oneOf"), list):
            referenced_nodes: list[Any] = []
            schema_root = schema_cache.get(path_text)
            for branch in node["oneOf"]:
                reference_value = branch.get("$ref") if isinstance(branch, Mapping) else None
                if not isinstance(reference_value, str) or not reference_value.startswith("#/"):
                    referenced_nodes.append(None)
                    continue
                branch_node = schema_root
                for token in reference_value[2:].split("/"):
                    token = token.replace("~1", "/").replace("~0", "~")
                    branch_node = branch_node.get(token) if isinstance(branch_node, Mapping) else None
                referenced_nodes.append(branch_node)
            closed = bool(referenced_nodes) and all(
                isinstance(branch_node, Mapping)
                and branch_node.get("additionalProperties") is False
                for branch_node in referenced_nodes
            )
        if not closed:
            errors.append(f"{label}: hash-subject schema must be closed (including every union branch)")
        digest_field = subject.get("digestField")
        if isinstance(digest_field, str) and "derived output" in digest_field:
            if not isinstance(node.get("x-qmanHashRule"), str):
                errors.append(
                    f"{label}: derived output requires an explicit x-qmanHashRule"
                )
        elif isinstance(digest_field, str):
            if digest_field not in node.get("properties", {}) or digest_field not in node.get("required", []):
                errors.append(f"{label}: digestField {digest_field!r} is not a required schema field")

    portable_entities_blob = _worktree_bytes(
        root,
        "contracts/directpath-portable-entities.schema.json",
        "DeviceRecord V3 schema",
        errors,
    )
    portable_entities = (
        _load_json_bytes(
            portable_entities_blob,
            "DeviceRecord V3 schema",
            errors,
        )
        if portable_entities_blob is not None
        else None
    )
    if isinstance(portable_entities, Mapping):
        definitions = portable_entities.get("$defs", {})
        device_record = (
            definitions.get("ENTITY-DEVICE-RECORD")
            if isinstance(definitions, Mapping)
            else None
        )
        dependency_domains = (
            definitions.get("dependencyDomains")
            if isinstance(definitions, Mapping)
            else None
        )
        if not isinstance(device_record, Mapping):
            errors.append("DeviceRecord V3 schema: ENTITY-DEVICE-RECORD is missing")
        else:
            if (
                device_record.get("properties", {})
                .get("schemaVersion", {})
                .get("const")
                != 3
                or "dependencyDomains"
                not in device_record.get("required", [])
            ):
                errors.append(
                    "DeviceRecord V3 schema: schemaVersion=3 and required dependencyDomains are mandatory"
                )
        for definition_name, field_name, expected_reference in (
            ("deviceRole", "pciStructureFact", "#/$defs/pciStructureFact"),
            (
                "resetContract",
                "pciFlrCapabilityFact",
                "#/$defs/pciFlrCapabilityFact",
            ),
        ):
            definition = (
                definitions.get(definition_name)
                if isinstance(definitions, Mapping)
                else None
            )
            fact_definition = (
                definitions.get(expected_reference.rsplit("/", 1)[-1])
                if isinstance(definitions, Mapping)
                else None
            )
            if (
                not isinstance(definition, Mapping)
                or definition.get("additionalProperties") is not False
                or field_name not in definition.get("required", [])
                or definition.get("properties", {})
                .get(field_name, {})
                .get("$ref")
                != expected_reference
            ):
                errors.append(
                    f"DeviceRecord V3 schema: {definition_name}.{field_name} "
                    f"must be a required closed reference to {expected_reference}"
                )
            if (
                not isinstance(fact_definition, Mapping)
                or fact_definition.get("additionalProperties") is not False
            ):
                errors.append(
                    f"DeviceRecord V3 schema: {expected_reference} must resolve "
                    "to a closed fact definition"
                )
        reset_contract = (
            definitions.get("resetContract")
            if isinstance(definitions, Mapping)
            else None
        )
        if (
            not isinstance(reset_contract, Mapping)
            or "resetProviderFactId" not in reset_contract.get("required", [])
        ):
            errors.append(
                "DeviceRecord V3 schema: resetContract.resetProviderFactId is mandatory"
            )
        if (
            not isinstance(reset_contract, Mapping)
            or "state" not in reset_contract.get("required", [])
            or reset_contract.get("properties", {})
            .get("state", {})
            .get("enum")
            != ["KNOWN", "UNKNOWN", "CONFLICT"]
        ):
            errors.append(
                "DeviceRecord V3 schema: resetContract.state must be mandatory "
                "KNOWN/UNKNOWN/CONFLICT"
            )
        expected_domain_order = [
            "FUNCTIONAL",
            "IOMMU",
            "MULTIFUNCTION",
            "PF_VF",
            "PHYSICAL_ISOLATION",
            "PLATFORM",
            "REQUESTER_ALIAS",
        ]
        actual_domain_order: list[Any] = []
        if isinstance(dependency_domains, Mapping):
            for item in dependency_domains.get("prefixItems", []):
                value = None
                if isinstance(item, Mapping):
                    for branch in item.get("allOf", []):
                        if isinstance(branch, Mapping):
                            value = (
                                branch.get("properties", {})
                                .get("kind", {})
                                .get("const", value)
                            )
                actual_domain_order.append(value)
        if (
            not isinstance(dependency_domains, Mapping)
            or dependency_domains.get("minItems") != 7
            or dependency_domains.get("maxItems") != 7
            or dependency_domains.get("items") is not False
            or actual_domain_order != expected_domain_order
        ):
            errors.append(
                "DeviceRecord V3 schema: dependencyDomains must contain the exact seven canonical kinds"
            )

    hash_subjects_blob = _worktree_bytes(
        root,
        "contracts/directpath-portable-hash-subjects.schema.json",
        "HostSnapshot committed-version schema",
        errors,
    )
    authority_blob = _worktree_bytes(
        root,
        "contracts/directpath-authority-entities.schema.json",
        "HostAuthority committed-version schema",
        errors,
    )
    receipt_blob = _worktree_bytes(
        root,
        "contracts/directpath-inventory-verification-receipt.schema.json",
        "Inventory receipt committed-version schema",
        errors,
    )
    committed_version_text = b"committed" in (hash_subjects_blob or b"").lower()
    committed_version_text = committed_version_text and b"r+1" in (
        hash_subjects_blob or b""
    )
    committed_version_text = committed_version_text and b"resourceversion" in (
        authority_blob or b""
    ).lower()
    committed_version_text = committed_version_text and b"committed" in (
        receipt_blob or b""
    ).lower()
    committed_version_text = committed_version_text and b"x-qmancommittedversionrule" in (
        portable_entities_blob or b""
    ).lower()
    if not committed_version_text:
        errors.append(
            "HostSnapshot committed-version rule must agree across snapshot, authority, binding, and receipt schemas"
        )


def validate_repository(
    root: str | os.PathLike[str] | Path = ".",
    *,
    map_path: str | os.PathLike[str] = "contracts/qman-integration-map.template.json",
    scenario_paths: Sequence[str | os.PathLike[str]] | None = None,
    expect_baseline: bool = False,
    trusted_root_digest: str | None = None,
    external_rollback_anchor: Any | None = None,
    external_catalog_anchor: Any | None = None,
    trust_anchor_freshness_envelope: Any | None = None,
    catalog_anchor_freshness_envelope: Any | None = None,
    verifier_nonce: str | None = None,
) -> list[str]:
    """Validate the repository's portable handoff, map, examples, and claims."""

    errors: list[str] = []
    try:
        root_path = Path(root).resolve(strict=True)
    except OSError as exc:
        return [f"repository root: cannot resolve {root}: {exc}"]
    contract_path = root_path / "contracts" / "directpath-portable-control-contract.json"
    map_candidate = Path(map_path)
    if not map_candidate.is_absolute():
        map_candidate = root_path / map_candidate
    contract = _coerce_document(contract_path, "portable contract", errors)
    mapping = _coerce_document(map_candidate, "integration map", errors)
    if not isinstance(contract, Mapping) or not isinstance(mapping, Mapping):
        return errors
    try:
        _validate_canonical_profiles(contract, root_path, errors)
        _validate_wire_schema_closure(contract, root_path, errors)
        _load_case_contract_registry(contract, root_path, errors)
    except Exception as exc:
        errors.append(
            f"portable contract: unexpected baseline validation failure: {type(exc).__name__}: {exc}"
        )
    errors.extend(
        validate_mapping_document(
            mapping,
            contract,
            root=root_path,
            expect_baseline=expect_baseline,
            trusted_root_digest=trusted_root_digest,
            external_rollback_anchor=external_rollback_anchor,
            external_catalog_anchor=external_catalog_anchor,
            trust_anchor_freshness_envelope=trust_anchor_freshness_envelope,
            catalog_anchor_freshness_envelope=catalog_anchor_freshness_envelope,
            verifier_nonce=verifier_nonce,
        )
    )
    if scenario_paths is None:
        scenarios = sorted((root_path / "handoff" / "examples").glob("*.json"))
    else:
        scenarios = []
        for path_value in scenario_paths:
            path = Path(path_value)
            scenarios.append(path if path.is_absolute() else root_path / path)
    for path in scenarios:
        scenario_errors = validate_scenario_document(
            path,
            contract,
            root=root_path,
            mapping_document=mapping,
            trusted_root_digest=trusted_root_digest,
            external_rollback_anchor=external_rollback_anchor,
            trust_anchor_freshness_envelope=trust_anchor_freshness_envelope,
            verifier_nonce=verifier_nonce,
        )
        errors.extend(f"{path.relative_to(root_path) if path.is_relative_to(root_path) else path}: {item}" for item in scenario_errors)
    return errors


def _main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Execute fail-closed semantic validation for the DirectPath portable handoff"
    )
    parser.add_argument("mode", choices=("baseline", "mapping", "scenario", "all"))
    parser.add_argument("--root", default=".", help="portable repository root")
    parser.add_argument(
        "--map",
        default="contracts/qman-integration-map.template.json",
        help="integration map path (relative to --root unless absolute)",
    )
    parser.add_argument(
        "--scenario",
        action="append",
        default=None,
        help="scenario path; repeat for multiple scenarios",
    )
    parser.add_argument(
        "--trusted-root-digest",
        default=None,
        help="out-of-band CONFIG-TRUST-ROOT-DIGEST (required for any signed/promoted target state)",
    )
    parser.add_argument(
        "--external-rollback-anchor",
        default=None,
        help="out-of-band monotonic rollback-anchor JSON path; must be outside the target checkout",
    )
    parser.add_argument(
        "--external-catalog-anchor",
        default=None,
        help=(
            "out-of-band supported-catalog rollback-anchor JSON path; must be "
            "outside target and evidence checkouts"
        ),
    )
    parser.add_argument(
        "--trust-anchor-freshness-envelope",
        default=None,
        help="live root-signed trust-anchor nonce response outside target/evidence checkouts",
    )
    parser.add_argument(
        "--catalog-anchor-freshness-envelope",
        default=None,
        help="live root-signed catalog-anchor nonce response outside target/evidence checkouts",
    )
    parser.add_argument(
        "--verifier-nonce",
        default=None,
        help="independently generated canonical base64url nonce (at least 128 bits)",
    )
    arguments = parser.parse_args(argv)
    try:
        root = Path(arguments.root).resolve(strict=True)
    except OSError as exc:
        print(f"ERROR: repository root cannot be resolved: {exc}", file=sys.stderr)
        return 2
    contract = root / "contracts" / "directpath-portable-control-contract.json"
    map_path = Path(arguments.map)
    if not map_path.is_absolute():
        map_path = root / map_path
    if arguments.mode == "mapping":
        errors = validate_mapping_document(
            map_path,
            contract,
            root=root,
            trusted_root_digest=arguments.trusted_root_digest,
            external_rollback_anchor=arguments.external_rollback_anchor,
            external_catalog_anchor=arguments.external_catalog_anchor,
            trust_anchor_freshness_envelope=arguments.trust_anchor_freshness_envelope,
            catalog_anchor_freshness_envelope=arguments.catalog_anchor_freshness_envelope,
            verifier_nonce=arguments.verifier_nonce,
        )
    elif arguments.mode == "scenario":
        scenario_values = arguments.scenario or [
            "handoff/examples/S05-legacy-qemu-start-failure-clean-rollback.json"
        ]
        mapping = _coerce_document(map_path, "integration map", errors := [])
        for value in scenario_values:
            path = Path(value)
            if not path.is_absolute():
                path = root / path
            errors.extend(
                f"{value}: {item}"
                for item in validate_scenario_document(
                    path,
                    contract,
                    root=root,
                    mapping_document=mapping,
                    trusted_root_digest=arguments.trusted_root_digest,
                    external_rollback_anchor=arguments.external_rollback_anchor,
                    trust_anchor_freshness_envelope=arguments.trust_anchor_freshness_envelope,
                    verifier_nonce=arguments.verifier_nonce,
                )
            )
    else:
        errors = validate_repository(
            root,
            map_path=map_path,
            scenario_paths=arguments.scenario,
            expect_baseline=arguments.mode == "baseline",
            trusted_root_digest=arguments.trusted_root_digest,
            external_rollback_anchor=arguments.external_rollback_anchor,
            external_catalog_anchor=arguments.external_catalog_anchor,
            trust_anchor_freshness_envelope=arguments.trust_anchor_freshness_envelope,
            catalog_anchor_freshness_envelope=arguments.catalog_anchor_freshness_envelope,
            verifier_nonce=arguments.verifier_nonce,
        )
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(f"portable handoff semantic validation FAILED ({len(errors)} errors)", file=sys.stderr)
        return 1
    print(f"portable handoff semantic validation PASS ({arguments.mode})")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
