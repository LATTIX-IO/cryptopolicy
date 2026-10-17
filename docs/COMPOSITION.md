# FOSS-437 — Canonical baseline and overlay composition

## Contract and security boundary

FOSS-437 adds a pure offline graph compiler, not a policy-authority service. PolicySet declares an explicitly versioned baseline root and zero or more mandatory overlay roots. PolicyNode contains a versioned PolicyDocument and references to required imports. Every PolicyReference pins PolicyId, semantic version and canonical SHA-256 document digest. The caller supplies the resolver; the cryptopolicy library performs no network, filesystem, clock, registry or mutable-global access.

A resolver is expected to use a stable preloaded mapping and must never silently substitute a newest version, cached invalid document or unpinned policy. The compiler compares the returned document identity and canonical digest to its pinned reference. A digest is NOT an issuer signature or proof of evidence authenticity. Caller security decisions still require independent authenticity/authorization checks.

Public Rust APIs:

- PolicyReference::from_document(&PolicyDocument) -> Result<PolicyReference, ContractError>
- PolicySet::parse_json_with_limits(bytes, &Limits)
- compile_policy_set(&PolicySet, &impl PolicyResolver, &Limits) -> Result<EffectivePolicy, CompositionError>
- EffectivePolicy::canonical_bytes() and .digest()
- EffectivePolicy::evaluate(&CryptoContext, explicit_time, &Limits) -> Result<EffectiveDecision, CompositionError>

## Intersection, never union

Every resolved policy is a **mandatory independent authorization layer**, including imported policies. The effective outcome uses these rules:

| Baseline / any mandatory layer | Effective outcome |
|---|---|
| Every component returns Permit | Permit |
| One or more components returns Deny | Deny, even when others Permit or Indeterminate |
| No Deny, at least one Indeterminate | Indeterminate |

No Permit may come from overlay-only grants if the baseline denies, no Deny can be overridden, and a missing or unknown import cannot be ignored. Components are evaluated separately through the conservative FOSS-435 evaluator; their rule ID namespaces remain policy-scoped and are not flattened into a union of Allow rules. Missing facts remain nonauthorizing. Changing import order, overlay order, rule order and conjunction order cannot affect effective bytes, digest or result.

**Strict preview behavior:** Each layer must independently contain an explicit satisfiable Allow. A Deny-only, Require-only, Warn-only or empty overlay cannot grant a Permit. This avoids accidentally treating an overlay as a global exception. A future guard-only overlay mode would require an independently designed, reviewed and versioned contract; none is silently inferred here.

## Atomic import resolution

Policy references must be supplied and match by **ID + exact semantic version + canonical digest**. A missing import, invalid nested policy, inconsistent digest, wrong ID/version, same PolicyId with conflicting versions or digests, dependency cycle, repeated direct import/root, and rejected caller limits all abort compilation with a typed CompositionError. No partial EffectivePolicy is returned. Shared exact imports on separate paths resolve once; graph traversal is bounded and deterministic.

FOSS-433 Limits apply cumulatively: max_imports constrains both graph node count and total dependency edges, max_import_depth limits longest path from each root, max_rules and max_metadata limit totals across the resolved graph, and max_json_bytes bounds final canonical bytes and serialized aggregate decisions. Per-document validation and resource limits still apply to all imported policies, and invalid policies cannot be laundered by a successful root. Caller-provided limits have hard upper bounds.

The compiled EffectivePolicy fields are private; callers see only read-only policy references/documents, immutable canonical bytes and the fingerprint. Mutating a source catalog after compilation does not change this snapshot. A failed compilation never produces a usable effective identity.

## Binary canonical format v1 (normative within this crate)

This format is **not RFC 8785**, CBOR canonicalization, a signature serialization, or interoperability across arbitrary JSON implementations.

- First bytes: ASCII domain string followed by one zero byte: cryptopolicy-effective-policy-v1\0
- Each variable blob is encoded as 4-byte **unsigned big-endian byte length** followed by its raw bytes.
- Arrays are encoded with a 4-byte **unsigned big-endian element count**, followed by their elements.
- Root section: one length-prefixed PolicyReference JSON, then count of overlays and their sorted, length-prefixed reference JSON.
- Resolved section: count of policies; for each policy sorted lexicographically by PolicyId, append its length-prefixed PolicyReference JSON; count of imports; sorted length-prefixed PolicyReference JSON for each dependency; then the length-prefixed output of PolicyDocument::canonical_json_with_limits.
- PolicyReference JSON fields are exactly policy_id, version, digest in that struct declaration order, UTF-8 without whitespace. Individual policy bytes reuse existing cryptopolicy-canon-v1 rules (including sorted policy rules, conjunctions and metadata).
- The effective fingerprint is lowercase hex SHA-256 of the **entire** domain-separated byte sequence. It is immutable for a compiled graph, but never implies provenance verification.

Role separation and import edges are in the bytes. Adding/removing any mandatory dependency, changing a root vs imported position, changing identity/version/content, or altering a genuine rule must affect the digest. Order-only permutations must not.

## Runnable reproduction

    cargo run -p cryptopolicy --example compose_offline
    cargo test -p cryptopolicy --test composition --locked
    cargo test --workspace --all-features --locked
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

The example resolves two independent, explicitly approving policies from an in-memory catalog and prints the effective digest and Permit. These source policies and evidence are **test fixture claims**, not authenticated authority.

## Remaining separate increments

FOSS-445 validates known algorithms and profiles from an independently trusted registry. FOSS-447 defines multi-fact correlation rather than the single-fact FOSS-435 gate. FOSS-459 binds all 33 normative threat-contract fixtures to evaluator runtime outcomes. FOSS-439 owns richer temporal criteria. FOSS-443 owns signed-reference exceptions; FOSS-458 owns named hybrid constraints. FOSS-466 remains an administrative publication prerequisite, and this PR does not enable publishing.
