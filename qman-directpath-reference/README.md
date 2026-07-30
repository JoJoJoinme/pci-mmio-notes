# Qman DirectPath SQLite reference transaction

This package contains the closed Static-admission command/result contracts and
one executable SQLite reference transaction. Its fixed evidence boundary is:

```text
REFERENCE_SQLITE_TRANSACTION_COMPONENT_ONLY
```

The component is deliberately independent of private Qman code. It is an
executable transaction pattern, not proof of a Qman product repository.

## Closed inputs and evaluator premise

`SqliteReferenceStaticAdmissionRepository.admit_static` accepts exactly one
already-parsed `StaticAdmissionCommand`. The command contains business identity,
an immutable request reference, an exclusive deadline, and its null-field
canonical hash. It cannot carry caller-authored read sets, authority vectors,
CAS expectations, resource versions, leases, bindings, or decisions.

Bundle selection comes from a constructor-injected pure evaluator pinned by:

```text
REFERENCE_EVALUATOR_PREMISE
```

The repository independently verifies the evaluator output against current
bundle membership and member generations. Every selected member's immutable
evidence hash must appear in the evaluator result, and every returned evidence
blob must exist and pass canonical-byte/digest verification.

Fixture data is written only through the explicitly named
`REFERENCE_ONLY_BOOTSTRAP` API. That API is for executable reference scenarios;
it is not a production admin surface.

## Read-only C15 query lane

`ReferenceSqliteSnapshotReader` opens a new independent connection for every
query. The configured database must be an existing absolute regular file; the
reader itself constructs the SQLite `mode=ro` URI, enables
`PRAGMA query_only=ON`, and begins one read transaction before it reads any
repository state.

Inside that transaction it reads the real repository commit clock, current
controller/request/inventory rows, the global availability fence, members,
bundles, leases, claims, quarantines, and one explicit
`reference_query_observer` row twice. The before and after canonical bytes must
match, and a fresh connection's `total_changes` must remain zero. Consequently,
a WAL publisher can make progress concurrently while the reader returns either
the complete old snapshot or the complete new snapshot.

The observer row is written only by `REFERENCE_ONLY_BOOTSTRAP`. It supplies
stable fixture values for a host-journal sequence, driver bind/unbind counts,
device-reset count, exclusive-VFIO-open count, observer instance identity, and
restart generation. It does **not** claim to have observed a real host journal
or driver. Missing store identity, observer identity, current request,
inventory authority, or global availability fence fails closed.

`SqliteReferenceDirectPathQuery.query_directpath` projects that snapshot into
the shared `DIRECTPATH_QUERY_READ_TRACE` schema. It retains actual canonical
instance bytes, all nine closed predicate observations, the exact global
availability fence, the deterministic `output_OP_QUERY_DIRECTPATH` bytes, and
raw reference request/result envelopes. All hash domains from the shared schema
are executable, including observed-instance, predicate, state, output, and trace
hashes. Repeating one frozen `ReferenceQueryContext` against unchanged rows
returns byte-identical request, result, output, and trace bytes.

Missing product rows are never relabeled as product evidence. Repository rows
use the shared schema's closed `referenceObservedRow` projection, which is
permitted only under
`REFERENCE_SQLITE_QUERY_TRANSACTION_COMPONENT_ONLY`. Journal, six-kind
side-effect counter, and reset-observation instances come only from the
explicitly bootstrapped reference observer row. Therefore these traces are
schema-valid component evidence, not `QMAN_PRODUCT_E3_QUERY_READ_TRACE`.

## Transaction and replay behavior

After in-memory command round-trip/hash checks, the first database statement of
every admission attempt is exactly `BEGIN IMMEDIATE`. Trusted time, generated
IDs, metadata checks, and all reads happen after that statement.

Within the same SQLite write transaction, the repository:

1. reads controller, request, policy, trust, catalog, inventory, availability,
   quarantine, and claim state;
2. evaluates and verifies one complete dependency bundle;
3. re-reads and byte-compares the current state, then re-reads trusted time
   before writing and again before `COMMIT`;
4. stages an `IN_PROGRESS` idempotency row, an ACTIVE `ASSIGNMENT_PREPARE`
   operation lease, one reference binding, complete bundle/member claims, a
   PREPARING assignment run, and audit/outbox events;
5. advances the global availability authority with a conditional update and
   allocates the commit sequence;
6. transitions the idempotency row by CAS from resource version 1 to
   `COMPLETED` resource version 2, stores the exact canonical result bytes, and
   writes the commit record.

The natural key is
`{operationId=STATIC_ADMISSION, idempotencyScopeHash, idempotencyKey}`.
`idempotencyScopeHash` is the frozen domain-separated VM scope projection.
Reusing that key with different exact command bytes fails closed; retrying the
same exact command returns the stored byte-identical result.

The stored binding is explicitly
`REFERENCE_STATIC_ADMISSION_BINDING`. It records availability resource versions
before and after the fence and requires `after = before + 1`. It is not the
portable or product `OperationAdmissionBinding`, and the package makes no claim
that it can authorize a host side effect.

## SQLite durability profile and limits

The store requires an absolute, non-URI, non-memory database path and configures
WAL, `synchronous=FULL`, foreign keys, and a bounded busy timeout. SQLite
serializes writers: overlapping admissions produce one commit and one stable
`DEPENDENCY_BUSY`; disjoint admissions both commit but are still serialized.
The quarantine writer uses the same `BEGIN IMMEDIATE`/global-fence protocol, so
an absence read cannot be bypassed by a concurrent phantom writer.

Tests inject an exception after every atomic write stage, use a real child
process with `os._exit` before commit, and use another hard exit after commit but
before return. The query tests also hard-exit a separate read process before its
read-transaction commit and confirm that no logical repository commit occurred.
These demonstrate transaction rollback, process-crash reopening, exact
idempotent recovery, and zero-write snapshot behavior for this component.

They do **not** prove storage behavior under power loss, disk/controller cache
failure, filesystem corruption, PostgreSQL `SERIALIZABLE`, distributed
coordination, a live Qman repository, host-journal ordering, E3/E4 evidence, or
closure of any DirectPath Case or Risk.

Run independently:

```text
cd qman-directpath-reference
python -m ruff check qman_directpath_reference tests
python -m ruff format --check qman_directpath_reference tests
python -m compileall -q qman_directpath_reference tests
python -m unittest discover -s tests -v
```
