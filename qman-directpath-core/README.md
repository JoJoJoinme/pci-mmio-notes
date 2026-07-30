# Qman DirectPath portable core

This package is the product-shaped, side-effect-free core extracted from the
V3 DirectPath contract.  It is intentionally separate from the historical
`pci-resource-model` reference API.

## Implemented portable boundary

The package owns deterministic computation and verification:

- strict `CANONICAL-JSON-V1` parsing and hashing;
- full IDENTITY-V1 derivation checks for PCI DSN and VPD serial sources,
  including source slicing, normalization, fingerprint, and device UID;
- real domain-separated Ed25519 verification;
- pinned trust root, complete key-ring history, external rollback-anchor and
  freshness checks;
- exact qualification-record and supported-catalog resolution;
- a closed qualification-profile chain that deterministically projects one
  verified exact record/current catalog, binds a recursive-E4 verifier trust
  port into a domain-separated verification receipt, and then binds the final
  profile hash plus guest ABI/support requirement to a factory-only Static
  admission context;
- layered capability decisions whose technical plan is independent of current
  lease availability;
- a complete current-inventory verifier for `DeviceRecord` schema V3.  It
  replays one exact retained 256-byte conventional PCI configuration capture,
  derives Header Type independently of class code, walks a bounded conventional
  capability chain, and derives PCIe FLR only from Device Capabilities bit 28.
  `PCI_FLR` is accepted only for an `ENDPOINT_PAYLOAD` Type-0 PCIe endpoint
  bound to the same provider fact.  Every
  record must contain exactly the seven typed dependency domains `IOMMU`,
  `PHYSICAL_ISOLATION`, `REQUESTER_ALIAS`, `MULTIFUNCTION`, `PF_VF`,
  `FUNCTIONAL`, and `PLATFORM`.  Domain state, target device UID, required
  action, and provenance are checked without inferring a domain kind from the
  legacy flat action projection.  Unknown or conflicting facts fail closed;
- a schema-bound portable inventory-verifier algorithm identity and a
  domain-separated trusted-process/component verification receipt.  The
  identity binds the exact loaded schema bytes and validation stages.  The
  receipt binds the verified trust context, exact HostAuthority current
  pointer, signed HostSnapshot, complete DeviceRecord set, signer, and
  verification time;
- a factory-only `VerifiedHostSnapshotCaptureClosureContext` for the C00
  publication-capture lane.  It consumes exact retained capture-batch,
  freshness-policy, DeviceRecord, provider-output, and provider-semantic
  bytes; enforces bounded canonical decoding and every declared set order;
  derives provider coverage from DeviceRecord provenance; requires an exact
  PCI-binding bijection over the complete host; independently replays each
  raw 256-byte PCI capture or closed failure; and reconstructs topology,
  provider, no-change, capability-policy, and mandatory-evidence freshness
  bindings.  `HOST_SNAPSHOT_CAPTURE_CLOSURE_VERIFIER_V2` binds the ordered
  transitive digest set for capability-policy, publication-trace, identity-v1,
  portable-entities, and portable-hash-subjects plus exactly ten validation
  stages.  It performs count/byte/node/depth/aggregate preflight before
  expensive schema traversal and indexes uniqueness, freshness, and dependency
  reciprocity.  Candidate records prove only an internally composable shared
  `candidateSnapshotEpoch`/`candidateResourceVersion`; both coordinates remain
  caller-stamped and require repository CAS.  Freshness is evaluated against
  caller-supplied capture completion rather than trusted transaction time.
  The fixed portable provider envelopes make generic facts
  byte-comparable but do not attest a target decoder.  Its schema-valid
  verification receipt permanently records
  `COMPONENT_CALLER_SUPPLIED_CAPTURE_BYTES_ONLY`,
  `COMPONENT_PREMISE_ONLY`, `productAuthorized=false`, and the unresolved
  target decoder/build, collector/publisher, trusted evaluation time,
  capability-policy authority, repository, rollback, visibility, and
  mapping/runner blockers.  It is not
  the full HostSnapshot publication transaction verifier;
- a factory-only structural HostSnapshot publication-decision stage.  It
  consumes the exact HostAuthority, global AvailabilityAuthority,
  capability-policy/authority, freshness-policy/authority, current inventory,
  predecessor rollback/freshness, zero-unresolved preflight, and a closed
  caller-supplied SERIALIZABLE-read receipt.  It recomputes the four-authority
  CAS expectation, rechecks capability-policy validity at the retained
  `beganAt`, and derives—without accepting a caller decision—the five
  `GENESIS`, `INCARNATION_GENESIS`, `SUCCESSOR`, `REFRESH`, and `NO_CHANGE`
  branches.  Freshness-policy rollout forces a successor without applying new
  selectors to predecessor records; exact-threshold age forces refresh; and
  `NO_CHANGE` retains new capture evidence while selecting the exact current
  DeviceRecord set as persisted state.  The full-publication composition is
  capped at 4,096 records.  Because the read receipt and time are supplied by
  the adapter and rollback signatures are only structurally inspected here,
  this stage remains
  `COMPONENT_CALLER_SUPPLIED_PUBLICATION_READ_SET_BYTES_ONLY`,
  `productAuthorized=false`;
- a factory-only HostSnapshot publication rollback-closure stage.  Starting
  from the decision's retained before/preflight bytes, it cryptographically
  verifies the independent rollback root quorum, preflight nonce, exact
  PREPARED reservation, signed HostSnapshot/HostAuthority after inventory,
  finalized COMMITTED anchor, fresh after read, complete external-anchor CAS,
  and phase-separated nonces.  Publication/commit-time trust verifies immutable
  after inventory at the retained `beganAt`; an optional recovery-time trust
  verifies the live finalized anchor/freshness at `verifiedAt`.  The latter
  must retain the former's exact key-ring history prefix, root and key-ring/
  trust-anchor namespaces, and nondecreasing trust-anchor state.  This permits
  forward key-ring rotation without re-signing old committed snapshots while
  rejecting root/key-ring/trust-anchor-authority namespace substitution,
  history forks, and rollback.  Both phases must match an independently
  configured trust-anchor path; the serialized context separately binds their
  signed freshness-receipt digests, `verifiedAt`, freshness expiry, and path.
  `NO_CHANGE` permits no reservation or anchor advance and reuses the exact
  retained current inventory.  The verifier deliberately has no `committedAt` input: it emits the
  exact transaction/reservation recovery keys and inclusive
  `[commitNotBefore, commitNotAfter]` window that a later authentic repository
  commit record must close.  Finalization may occur after prepare expiry;
  expiry only forbids a new repository commit.  Aggregate rollback input is
  bounded to 16 MiB and 250,000 JSON nodes.  Direct trust-authority path/nonce
  transport, actual repository ordering/CAS, visibility, operation-envelope
  time binding, and target execution remain blockers, so the result is fixed to
  `COMPONENT_CALLER_SUPPLIED_ROLLBACK_AUTHORITY_BYTES_ONLY`,
  `productAuthorized=false`;
- a factory-only HostSnapshot publication mutation-closure stage.  It consumes
  only replayed decision and rollback contexts plus exact caller-supplied
  repository transaction, AvailabilityAuthority, audit, pending-outbox, and
  durable commit-row bytes.  For committed branches it derives exactly one
  DeviceRecord INSERT per persisted record plus the HostSnapshot INSERT,
  HostAuthority and AvailabilityAuthority UPDATEs, and audit/outbox/commit
  INSERTs—exactly `N+6`, capped at 4,102.  It independently reconstructs all
  five digest projections, the acyclic mutation-set fixed point, outbox
  payload, audit/outbox/commit self-digests, DeviceRecord-set digest, and the
  resolved four-authority vector; `NO_CHANGE` requires all four row artifacts
  to be absent and derives an empty write set.  The supplied transaction must
  bind the four-authority expectation and commit inside the retained external
  reservation window before finalization.  Its locally closed CAS-result shape
  is retained inside the context digest and replayed exactly, but this stage
  does not bind the full operation-payload schema/envelope.  It also does not
  authenticate the repository port, observe the CAS/atomic commit, define
  aggregate/event-ID or `createdAt` semantics, prove durable commit-context/
  commit-clock visibility, or deliver the anchor-gated outbox event.  Its fixed
  boundary is
  `COMPONENT_CALLER_SUPPLIED_REPOSITORY_ROWS_AND_TRANSACTION_ONLY` with
  `productAuthorized=false`;
- a factory-only `VerifiedHostSnapshotAnchorBinding` that accepts only one
  schema-valid `COMMITTED` external HostSnapshot rollback anchor and its exact
  live verifier-nonce freshness envelope.  It verifies root quorums,
  candidate/anchor/receipt/schema/raw-byte digests, monotonic CAS shape,
  same-incarnation predecessor linkage, incarnation-genesis rules, all eight
  inventory coordinates, the configured path, and the capture/prepare/
  receipt/freshness time chain.  Its fixed boundary is
  `COMPONENT_EXTERNAL_BYTES_VERIFICATION_ONLY` with
  `productAuthorized=false`: it cannot prove direct fetch, nonce transport, or
  authority-side linearizable CAS;
- verification of a closed, self-hashed capability policy and a persisted
  Static VM DirectPath request.  The only portable Static admission constructor
  derives `ClosureRequest` roots from the verified selector and derives closure
  limits from the verified policy; callers cannot independently substitute
  either;
- a bounded seven-domain/reset fixed-point resolver.  Its portable hard
  ceilings are 4,096 devices and 65,536 edges.  Success produces the exact
  dependency bundle and complete `RESET_CONTRACT_SET`; unknown/conflicting
  action or provenance, an unverified reset domain, or a bound overflow fails
  closed without an authorizable partial result;
- `RequestReadSet` and `AvailabilityReadSet` bindings plus deterministic
  `read_guard` replay.  The guard accepts only a factory-created
  `VerifiedStaticCapabilityContext`, which combines the complete inventory
  closure, the qualification binding derived from the same Static admission,
  and one schema-bound `VerifiedGuestResourcePlanContext`.  That plan context
  replays exact canonical bytes, the plan null-hash projection, loaded schema
  bytes, upstream closure/profile coordinates, and bounded window ordering,
  power-of-two, alignment, safe-end and peer-overlap rules.  It is explicitly
  a caller-bytes structural boundary with `productAuthorized=false`; it does
  not run or prove the BAR/MMIO/RMRR/IRQ solver.  The guard never accepts
  separately supplied admission, facts, roots, limits, result, profile or plan
  hashes.  It replays all factories and the
  closure, then binds the exact current Static request row, committed
  HostAuthority and current-policy pointer versions, trust/catalog anchors,
  qualification records/signers/profile/receipt, inventory receipt and
  verifier identity, snapshot semantics, selected device
  generations/resourceVersions, blocking lease/quarantine observations,
  bundle, reset-contract set, and complete before/after
  `CurrentAuthorityVector`.  Six HostSnapshot anchor currentness fields come
  from the factory binding, and its freshness expiry participates in the
  exact evidence horizon;
- the selected payload hardware premise derives hardware, technical,
  administrator-enabled and owner-active gates from the verified V3 inventory.
  Owner activity covers the complete resolved owner-activation group, not only
  request roots, and requires PASSTHROUGH intent/effective state plus
  `ALREADY_ACTIVE`.  The read guard requires exact equality for all four gates
  and for the structurally verified resource-plan hash before capability
  evaluation; caller-reported `YES` and digest substitution fail closed;
- factory-only `StructuralQualificationProfileContext` and
  `StructuralStaticQualificationBindingContext` values.  They replay the
  exact authenticated QualificationRecord/current SupportedCatalog bytes
  through the projection, caller-injected recursive-E4 component port,
  verification receipt, and final profile hash, then bind all four Static
  request `profileBinding` fields, guest ABI, policy
  catalog/key-ring/Case-matrix tuple, and explicit PRODUCTION=`SUPPORTED`.
  These results are always `STRUCTURALLY_VALID`/`COMPONENT_ONLY`, with
  `componentAuthority=false`, `productAuthorized=false`, and the permanent
  `TRUSTED_E4_ADAPTER_REQUIRED` blocker included in every profile/static
  binding subject and digest.  The old `VerifiedQualificationProfileContext`
  and `VerifiedStaticQualificationBindingContext` exports are deprecated
  compatibility aliases for those same structural-only classes; their names
  do not imply authority.  The profile semantic digest is derived from the
  schema-pinned profileId/runtime/ABI/workload/revocation/support projection;
  record/catalog/receipt/profile hashes remain separate currentness
  coordinates and a caller cannot supply the semantic digest;
- a factory-only `VerifiedOperationAdmissionBinding` that accepts only an
  eligible/attachable guarded Static decision, an exact single-bundle
  `ASSIGNMENT_PREPARE` lease specification, canonical-byte-equal before/after
  authority vectors, exact Request/Availability read-set blobs, a CAS
  expectation whose schemaRef is pinned to the exact portable
  `casExpectation` fragment, and an exclusive validity horizon.  The binding
  retains a closed authority disposition containing the static context and
  hardware/plan/qualification/HostSnapshot-anchor premise digests and
  boundaries.  It is mechanically fixed to
  `COMPONENT_STATIC_CAPABILITY_RELATIONSHIP_ONLY`,
  `productAuthorized=false`, with explicit product-adapter/planner/repository
  blockers, so an eligible component decision cannot be serialized as product
  authority.  The binding has its own null-hash identity; `scopeHash` remains the shared physical
  conflict identity and is never reused as that hash;
- a factory-only `VerifiedQueryReadTrace` for the C15 component lane.  It
  consumes exact canonical trace/request/result bytes, validates every retained
  observed instance and query output against the pinned schema fragment,
  reconstructs all nine predicate closures and the global availability fence,
  binds the six HostSnapshot anchor-vector fields to one explicit
  component/reference binding observation,
  requires byte-equal complete before/after read states, and derives the
  journal/counter/reset zero-write witness.  Schema, decoder, SQL/API log, and
  digest-only substitutes fail closed.  The pure verifier rejects the
  `QMAN_PRODUCT_E3_QUERY_READ_TRACE` boundary;
- a Correctable-only AER portable component: canonical policy and dynamic
  PCIe/AER layout verification, per-byte read projection, factory-only
  filter-before-VFIO write plans, four orthogonal reference state machines,
  exact M24-M29 evidence binding, and fail-closed component admission.  Its
  authority boundary is always `COMPONENT_PREMISE`; it never returns a product
  authorization;
- verifier-produced request, policy, admission, trust, qualification, identity,
  inventory, record, and typed closure contexts have no public constructor and
  cannot be recreated with `dataclasses.replace`.  This prevents ordinary
  in-process callers from relabeling an unchecked value as `Verified`.

## Correctable AER portable component

The implementation is split across
[policy and config-space projection](qman_directpath_core/aer_policy.py),
[reference transitions](qman_directpath_core/aer_reference_model.py),
[evidence and qualification binding](qman_directpath_core/aer_evidence.py), and
[component admission](qman_directpath_core/aer_admission.py).  The executable
M24-M29 scenarios are in [the AER core tests](tests/test_aer_core.py).

### Config-space isolation before VFIO

- `VerifiedAerPolicy` accepts a closed, Correctable-only policy and derives a
  domain-separated canonical `aerPolicyDigest`.  Extended-capability header
  exposure and AER body exposure are independent: a hidden header can be
  removed from the extended-capability chain, while a hidden body can project
  only `ZERO` or hypervisor-owned `SHADOW` values.
- `VerifiedAerConfigLayout` verifies the dynamically discovered PCIe and AER
  capability offsets, headers, chain links, 4 KiB bounds, and Endpoint versus
  Root-Port field set.  Its digest is bound to device identity, BDF, host boot,
  assignment, lease generation, and owner epoch.  This verifies relationships
  among supplied bytes; it is not proof that a live VFIO/config-space read
  produced them.
- Guest reads overlay policy-selected physical or shadow fields.  Hidden,
  Uncorrectable, missing, and unknown byte lanes are explicitly zeroed and
  reported by lane disposition.  There is **no raw-config fallback** for an
  unknown lane.  Root Status and Correctable Error Source are projected only
  from one factory-issued atomic snapshot receipt bound to policy, layout,
  device/lease/owner generations, snapshot identity, and authority revision.
  Requester attribution is returned only while guest-visible `COR_RCV` is set
  and the complete 16-bit Source field is present; raw paired reads and
  caller-supplied semantic booleans cannot bypass that rule.
- Every guest write is planned by `plan_guest_config_write` before any VFIO
  call.  A factory-only plan splits the complete request-bit ownership into
  physical W1C, shadow W1C, and discarded masks.  Physical writes target a
  complete 16/32-bit W1C field and contain only
  `guestBits & physicalW1cAllowMask`; the raw guest value is never forwarded.
  An access overlapping Uncorrectable Status/Mask/Severity is denied as a
  whole, unknown fields default to `DENY`, and `require_pre_vfio_plan` creates
  a one-use executable plan rebound to the current policy, layout, device,
  boot, assignment, lease, owner, operation ID, and authority revision.
  Execution rechecks those coordinates and atomically consumes the plan;
  classification objects, stale plans, and replayed plans expose no physical
  write list.

### Four independent state machines

`AerReferenceModel` keeps four orthogonal, immutable state machines:

1. guest configuration virtualization, including shadow reads and shadow W1C;
2. physical Endpoint/Root retained Correctable state;
3. notification/service observations; and
4. lifecycle cleanup, reuse, and quarantine.

The transition model covers the M24-M29 premises: Correctable deposition and
OR accumulation; independent E (Endpoint reporting), M (Correctable mask), and
R (Root notification enable) controls; first-message `COR_RCV`/Source capture;
multiple-message `MULTI_COR_RCV` with first Source retained; independent
Endpoint CES, Device Status CED, and Root Status W1C; Source invalidation when
`COR_RCV` clears; and clear/rearm behavior.  R controls notification
eligibility only and does not suppress Root retained status or Source.

IRQ delivery, service attribution, device health, and physical recovery are
never inferred from register transitions.  Those lanes start as `UNKNOWN`, are
updated only by explicit observations, and become `CONFLICT` when observations
disagree.  Cleanup succeeds only when both physical and guest-shadow error
state are clean; otherwise the lifecycle enters `QUARANTINED`.  Reuse requires
verified cleanup plus a separate passing reuse gate.

### Frozen VMware g101 retained-state parity

`aer_retained_sequence.py` turns the frozen public-observation profile into an
executable Qman component trace.  It fixes Correctable-only gate `g101`,
Requester `0x0101`, B0/B1, and the four `first-multiple`, `independent-w1c`,
`bit-or`, and `rearm` sequences.  Every immutable checkpoint uses the same
eight external register-state fields as
`vmware-aer-root-sequence-frozen-observed-g101-o0-o4-v1.json`; the conformance
test compares every O0 and O4 checkpoint field-for-field and locks the observed
profile hash.

The pure simulator has no owner input and does not validate a runtime owner
envelope.  The conformance test independently compares the same pure-model
trace with the frozen O0 and O4 artifact branches.  This demonstrates that the
Qman component reproduces the frozen external state slice.  It does not
establish VMware owner-independent internals, a bound native-driver O0 path,
IRQ/service attribution, guest-write behavior, lifecycle recovery, physical
qualification, or product authorization.

### M24-M29 evidence and admission

The canonical evidence envelope binds the exact ordered M24-M29 case set and
the exact ESXi build, environment kind, PCI identity/requester, owner phase,
assignment/lease/epoch/boot, gate, profile, backend, Qman build,
implementation, parity oracle, config layout, and source hashes.  Each case
also binds its run-result, artifact-manifest, and oracle digests.  Candidate,
inconclusive, mismatched, incomplete, non-exact, or non-contained evidence
cannot become behavior authority.

Qualification structurally requires physical-environment evidence, cleanup,
reuse, all five dimensions (`GUEST_WRITES`, `IRQ_DELIVERY`,
`SERVICE_ATTRIBUTION`, `DEVICE_HEALTH`, and `PHYSICAL_RECOVERY`), and the exact
M24-M29 E4 hash set.  The portable replay request/receipt binds canonical
policy/evidence bytes, layout, device, owner/lease/boot coordinates, every case
digest, verifier identity, nonce, authority revision, and validity window.
`None`, booleans, legacy `verify() -> None` ports, digest supersets, stale
receipts, and replay under a new nonce/revision fail closed.

Admission has a second structural current-authority request/receipt.  It binds
the same coordinates plus the current authority vector and an exact
`revision + 1` CAS transition, under fixed byte/node/depth/count and 60-second
TTL budgets.  Caller-supplied expectations, runtime gates, and timestamps are
diagnostic consistency inputs only.  The portable package has no trusted
signature root, monotonic repository, durable nonce consumer, or authoritative
clock, so even an exact structural receipt cannot become authority.

This path has three invariant output labels:

- `authorityBoundary = COMPONENT_PREMISE`;
- `componentEligible = false`;
- `productAuthorized = false`.

It always retains `TRUSTED_E4_ADAPTER_REQUIRED`; a missing current receipt also
adds `CURRENT_AUTHORITY_RECEIPT_REQUIRED`.

## Normative schemas

The current portable path uses ten closed schemas:

- [capability policy](../contracts/directpath-capability-policy.schema.json);
- [dependency closure request](../contracts/directpath-dependency-closure-request.schema.json);
- [inventory verification receipt](../contracts/directpath-inventory-verification-receipt.schema.json);
- [inventory verifier algorithm identity](../contracts/directpath-inventory-verifier-algorithm.schema.json);
- [HostSnapshot rollback anchor](../contracts/directpath-host-snapshot-rollback-anchor.schema.json);
- [resolved reset-contract set](../contracts/directpath-reset-contract-set.schema.json);
- [qualification profile projection](../contracts/directpath-qualification-profile-projection.schema.json);
- [qualification verification receipt](../contracts/directpath-qualification-verification-receipt.schema.json);
- [operation admission binding](../contracts/directpath-operation-admission-binding.schema.json);
- [query read trace](../contracts/directpath-query-read-trace.schema.json).

`directpath-portable-control-contract.json.normativeSources` is an explicit
allowlist.  Portable-package generation hashes only paths named in that list;
it does not recursively discover normative sources through JSON Schema
`$ref`.  Each of the ten schemas therefore has to be listed explicitly in the
portable contract and included in the handoff validation closure.

The candidate AER contract package additionally contains closed policy, case
matrix, component-receipt, and verifier-algorithm schemas, an exact 133-tuple
M24-M29 matrix, generated golden vectors, and a source-bound conformance test.
It rejects Endpoint/Root identity aliasing, candidate/reference self-comparison,
cross-tuple run-result replay, semantic rewrites followed by re-signing, and
pre-parse resource bombs.  It deliberately has no resolver promotion lane:
successful verification returns only `STRUCTURALLY_VALID`,
`componentEligible=false`, and `productAuthorized=false`.

Those AER files remain **candidate component contracts**.  They are not named
in `directpath-portable-control-contract.json.normativeSources`, are not part
of the portable-package/handoff closure or product Case registry, and cannot
close E4.  Runtime policy/layout/evidence/admission objects also retain
factory-only Python invariants not yet represented by that candidate schema
set.  The current product QualificationProfile/QualificationRecord exact key
does not normatively bind `aerPolicyDigest` or the M24-M29 matrix.

## Product boundary

It does **not** own private keys, an HSM/KMS, an external monotonic authority,
host I/O, a database, VFIO handles, reset execution, QEMU launch, or audit
storage.  Product adapters must supply those ports and must recheck the exact
current authority vector before schedule, reserve, attach, and commit.
The inventory verifier, HostSnapshot anchor verifier, read sets, and read
guard check relationships among caller-supplied immutable values.  The anchor
verifier does not generate its nonce, fetch from an independent service, or
prove that service performed a linearizable CAS.  The inventory receipt is not
a signature,
binary/build attestation, executable provenance, independent-read proof,
repository linearizability proof, publication proof, or CAS receipt.  Only an
independent Qman authority adapter can prove predecessor bytes, trusted time,
linearizable current reads, atomic CAS transitions, durable operation leases,
and ordering around side effects.
In particular, a capture-closure receipt's caller-stamped candidate coordinates
and caller completion time cannot satisfy the HostAuthority next-version CAS or
the publication transaction's trusted `evaluatedAt` requirement.
`VerifiedOperationAdmissionBinding` likewise proves only relationships among
the supplied immutable bytes.  A product repository must enforce a UNIQUE
one-to-one lease/binding row, create the live lease, reservation, binding,
versioned idempotency record, audit, and outbox atomically in one SERIALIZABLE
transaction, store the non-null binding hash on the `ASSIGNMENT_PREPARE`
OperationLease, and revalidate the exact live lease/binding capability before
a journal-fenced host side effect.  The repository must derive all read sets,
current vectors, CAS operands, leases, and bindings from a business-only
command; it must also use the versioned global availability authority (or a
later closed equivalent) to prevent absence phantoms.
`VerifiedQueryReadTrace` likewise proves byte and relationship closure only.
It does not prove that retained bytes came from a real product transaction or
that the product database/host observers enforced read-only behavior.
The implemented envelope branch validates the closed SQLite-reference
request/result shapes and their raw-byte correlations.  A non-reference
portable/product operation-envelope branch is not implemented here and fails
closed; this component never upgrades a trace to product E3 evidence.
The factory-only Python values are misuse resistance, not a hostile-process
security boundary; they do not replace those repository authorities.

Dynamic request verification/selection is not implemented by this core.
The qualification-profile verifier orchestrates deterministic replay around an
injected recursive-E4 resolver/replayer component port, but it neither
implements nor attests that production resolver.  `None` or a non-callable
port, exceptions, and non-`None` success values fail closed.  A caller port
whose method returns `None` after replay can produce only the structural
profile and structural Static binding above; it cannot remove
`TRUSTED_E4_ADAPTER_REQUIRED` or mint a product-authorized profile.  A real
product adapter must authenticate its resolver/repository identity and perform
a separate promotion outside this package.  No such adapter, Qman repository
adapter, inventory/provider collector, CAS transaction, VFIO/QEMU side effect,
rollback executor, or end-to-end product evidence is present.

The guest-resource-plan verifier is likewise not the product planner.  It
accepts only bounded canonical bytes for the closed plan schema, binds the
schema bytes and digest, replays upstream admission/inventory/reset/profile
coordinates, and checks structural window containment and arithmetic.  It does
not discover BAR demand, solve bridge/MMIO/RMRR/IRQ placement, prove
`allMandatoryResourcesAssigned`, or observe a QEMU/firmware realization.  Its
context is permanently
`COMPONENT_CALLER_SUPPLIED_RESOURCE_PLAN_BYTES_ONLY`,
`productAuthorized=false`; the product planner and its independently observed
post-launch receipt remain required.

The same boundary applies specifically to AER.  The portable package has no
real filter-enforcing VFIO adapter, IRQ-delivery observer, service-attribution
observer, device-health observer, physical-recovery executor/evidence,
production E4 resolver/replayer, or exact-key QualificationProfile integration
that carries `aerPolicyDigest`.  Therefore it cannot prove real guest writes,
interrupt delivery, service or health continuity, cleanup/recovery on physical
hardware, E4 closure, or product admission.

Passing these tests establishes a portable component premise only.  It does
not close a Qman Case or Risk, provide E3 product evidence, provide E4 physical
qualification, or authorize a release.

Run:

```text
cd qman-directpath-core
python -m pip install -e ".[test]"
python -m pytest -q tests/test_host_snapshot_anchor.py tests/test_read_guard.py
python -m pytest -q tests/test_publication_capture.py tests/test_publication_decision.py tests/test_publication_rollback.py tests/test_publication_mutation.py
python -m pytest -q tests/test_aer_core.py tests/test_aer_retained_sequence.py tests/test_aer_normative_contract.py
python -m pytest -q -p no:cacheprovider
python -m unittest discover -s tests
```
