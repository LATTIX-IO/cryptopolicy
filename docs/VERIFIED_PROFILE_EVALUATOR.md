# FOSS-507 — Guarded named-profile policy evaluation

## Boundary

The existing `evaluate_with_limits()` API is **unchanged** and continues
to treat any named profile as unsupported for a Permit. The new
`evaluate_qualified_profile_with_limits()` is a separate explicit opt-in
policy-*data* evaluation requiring in-process source and key qualification.
It is neither a cryptographic operation, a signed authorization artifact,
a trusted PDP decision, nor an exception waiver.

Every call takes an original immutable `PolicyDocument` and a bounded
`ProfileQualificationRequest` with exactly one observed/negotiated
`CryptoContext` fact, exact `ExceptionScope` tenant/environment/
operation/algorithm/key binding, exact `KeyProfileBinding` to the current
key generation, a typed parameter witness, caller-injected UTC time,
and resource limits. Two separate caller-implemented trust callbacks must
authenticate original source/provider/parameter/revocation evidence and
actual-key owner/generation/profile.

The wrapper **re-runs** FOSS-505 `qualify_embedded_profile()` on every
request using the repository-pinned, SHA-256-verified `pqc-kit` catalog.
It never takes an externally supplied `ProfileQualificationReport` as
proof. Caller-declared `verified=true`, `source_quality=externally_verified`,
source IDs, canonical strings and policy issuer fields alone are untrusted.
A verifier implemented to trust these unverified strings would violate its
security contract. In particular, the source verifier MUST authenticate the
integrity of the **entire policy-relevant observed fact**, not merely an
`evidence_ref` string: classification, claimed security category, provider,
key protection, exportability, key length, operation, profile and provenance
must be covered by the original attested source or independently verified
within that consuming application's trust domain. Otherwise neither a
positive qualification nor any resulting policy Permit can be trusted for
enforcement.

If and only if the actual qualification returns
`ReadyForVerifiedEvaluator`, a crate-private, sealed-proof-gated evaluator interprets the
canonical named profile and explicit `Requirement::Profile` /
`RuleSelector.profile_id` equality. For every other qualification result
the normal conservative evaluator is called; a missing or forged
qualification never promotes a fact to Permit.

The original evaluator's algorithm preview recognition logic, v1 policy
schema, canonical policy digest, stable reason ordering, temporal rules and
Deny > failed Require > unknown Require > matched Allow > default-Deny
precedence are preserved. The guarded path permits a standardized
catalog-qualified named profile only with an actual matching explicit
Allow and all applicable mandatory Require rules satisfied. It cannot
override a matching explicit Deny, unknown required attributes, expiry,
missing Allow or unrelated policy requirements.

The entrypoint returns a `QualifiedProfilePolicyDecision` containing
the fresh qualification result and the normal `PolicyDecision`. Even
when the outcome is `Permit`, **this remains a non-authorizing policy
evaluation record**. The caller MUST independently authenticate the
policy issuer and enforce operation permissions through its own trusted
PDP/PEP and key-management boundary. This library does not authenticate
policy authors, issue signed authorization tokens, perform cryptography,
approve exceptions or open network connections.

## Explicit exclusions

- `Requirement::NamedHybrid` is never unlocked by an ordinary
  standardized primitive profile; exact registered hybrid constructions
  require a separate reviewed versioned binding.
- No fallback from unsupported FIPS/standards status, alias, renamed
  draft, mismatched canonical ID, missing source proof or different key
  generation to a broader generic algorithm profile.
- FOSS-502 waivability registry and FOSS-500/A exception admission
  remain fail-closed for named-profile waivers. FOSS-503/C must
  independently integrate this verified interpreter with exact-owner
  Deny/Require **hypothetical** waiver simulation and independently
  attested compensating rules without changing unrelated policy layers.
- This increment does not change any of the original 33 normative
  FOSS-459 security cases or claim new conformance mappings.
- All five package manifests remain `publish=false`. FOSS-464 and
  FOSS-466 control future release authorization.

## Developer verification

    cargo test -p cryptopolicy --test profile_qualification --locked
    cargo test -p cryptopolicy --test evaluator --locked
    cargo test --workspace --all-features --locked
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo fmt --all -- --check

The profile-qualification suite tests ordinary AES-256-GCM and exact
ML-DSA-65 profile Allow, default deny, independent trusted source/key
callbacks, a spoofed report, conflicting profile IDs, absent external
evidence, mandatory unsatisfied or unknown requirements, Deny rule
permutations, explicitly supplied effective/expiry boundaries, and
unsupported named-hybrid requirements. The same input remains
Indeterminate via the original, unverified evaluator and retains the
same canonical policy digest.

All positive verifier stubs in tests are **synthetic evidence** and MUST
NOT be copied into production as key/profile or signer authentication.
