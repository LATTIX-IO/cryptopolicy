# FOSS-435 — Deterministic single-context evaluator

**Status:** FOSS-435 implements a working **offline decision engine**. This is a bounded v1 preview, not a cryptographic provider, identity/authentication service, registry attestation or policy enforcement point (PEP). The 33 normative threat-contract fixtures from FOSS-426 remain separate; this increment introduces executable evaluator behavior tests, but does **not** claim every FOSS-426 scenario has been mapped to the runtime. FOSS-459 owns complete corpus conformance.

## Public API

- evaluate(&PolicyDocument, &CryptoContext, EvaluationTime) -> Result<PolicyDecision, ContractError>
- evaluate_with_limits(..., &Limits) -> Result<PolicyDecision, ContractError>

Pure functions: no network, system time, filesystem, environment variables, mutable global state, random values or cryptographic primitives. A required explicit UTC millisecond timestamp must equal context.evaluation_time or the function returns a typed error. The produced PolicyDecision retains the policy ID, policy version and SHA-256 canonical digest, exact evaluation time, bounded RuleId and evidence references, stable reason codes and a versioned schema. The caller must independently authenticate input policy and evidence; the issuer, verified flag and source_quality fields are **claims**, not proof of authenticity. A Permit record is not an authority token.

## Decision precedence

1. Reject invalid policy/context, duplicate IDs, inconsistent timestamps, ambiguous multi-fact requests and exceeded limits with a typed error, not a Deny/Permit response.
2. Reject policies before their creation/effective timestamp with **Deny / policy_not_effective**, and at or after expires_at with **Deny / policy_expired**. A valid start is inclusive, expiry exclusive; FOSS-439 owns full time-based rule semantics.
3. Evaluate each typed AND selector. A known mismatch gives NonMatch even when other fields are unknown; a missing potentially decisive Deny or Require selector produces Indeterminate unless a separate definitive Deny dominates. Missing Allow/Warn selector facts simply prevent that rule from authorizing.
4. A definitely matched Deny always dominates every Allow or Require regardless of rule position. Requirements attached to a Deny cannot weaken the denial.
5. A matched Require is mandatory. One known failed requirement produces Deny; missing mandatory evidence produces Indeterminate. All requirements must be jointly satisfied **on the same target fact**.
6. An Allow candidate must match and satisfy every attached requirement. Known failures cannot authorize. Missing candidate requirements produce Indeterminate when no other explicit valid Allow exists.
7. No-match and Warn-only return Deny/default_denied. **Even an explicitly authored default_effect=allow never grants authorization.** Warnings cannot authorize.

Precedence, in descending order: definitive Deny; definitive failed Require; potentially decisive unknown Deny/Require; explicit satisfied Allow with evidence and algorithm-profile gates; incomplete Allow; default Deny. Reason arrays sort by RuleId then stable reason code; matched rules and opaque evidence IDs sort deterministically. Reordering policy rules or conjunctions does not change a serialized decision or canonical digest.

## Single-target fact restriction

FOSS-435 accepts **zero or one** CryptoFact in CryptoContext. More than one produces ContractError::InvalidDocument("multiple target facts unsupported"), even if both appear valid. No property, algorithm or provenance is ever joined across facts. This is a deliberate fail-closed contract until FOSS-447 models target identity, fact correlation and coverage across inventory observations. An absent fact is not evidence of absence.

A candidate Permit additionally requires a fact with:
- origin = observed or negotiated, never merely configured/inferred/requested/provider_capability
- verified = true AND an evidence_ref (both still untrusted caller assertions)
- source_quality = externally_verified (still a caller assertion)
- exact algorithm identity with an operation and basic parameter pairing in the **provisional closed recognition table**

For now the recognition pairs are AES-256-GCM/AES-128-GCM with encrypt/decrypt and an exact key size of 256/128 bits, SHA3-256/SHA3-512 with hash, and ML-KEM-768/ML-KEM-1024 with encapsulate/decapsulate. This is strictly a **preview input-recognition table**, not evidence of approved, standardized, FIPS-validated or correctly implemented cryptography. Every other name yields Indeterminate/unsupported_profile when it would otherwise authorize.

**Any named profile or hybrid condition is non-authorizing** even on exact textual equality; the outcome is Indeterminate/unsupported_profile until FOSS-445 (registry identities/status) and FOSS-458 (named hybrids) supply the needed trusted metadata. Known wrong mandatory values produce Deny/requirement_not_satisfied; unknown relevant values produce Indeterminate/missing_required_attribute. This intentionally prioritizes false denials over unauthorized Permits.

## Code and examples

Use the committed JSON policy and context fixtures:

    cargo run -p cryptopolicy --example evaluate_offline
    cargo test -p cryptopolicy --test evaluator --locked -- --nocapture
    cargo test --workspace --all-features --locked
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

Expected example outcomes: an explicitly allowed and provisionally recognized AES-256-GCM encryption request with declared observed evidence returns Permit; adding a matching hard Deny switches it to Deny. These are **locally constructed, untrusted fixture claims**. Consumers may rely on the decision only after applying independent input-authentication, authorization and enforcement controls.

## Security invariants and follow-on ownership

| Invariant | FOSS-435 behavior |
|---|---|
| SEC-002 | Known matching Deny dominates any Allow; rule-order invariant |
| SEC-003/004 | Indeterminate and typed Err cannot authorize; no missing mandatory fact grants Permit |
| SEC-007 | Injected evaluation time; deterministic document start/end boundaries |
| SEC-008/009 | Exact algorithm pairing; unsupported profile/unknown name cannot Permit |
| SEC-010/011 | Configured, negotiated, observed and provider-capability stay distinct; no cross-fact evidence joins |
| SEC-014 | FOSS-433 resource budgets bound the evaluation and serialized outputs |
| SEC-016 | Stable sorted reason codes, matched rules, evidence IDs and policy digest |
| SEC-017 | Consumer MUST enforce Permit-only; this library is not a PEP |

The main unresolved guarantees are external authentication/attestation and a trusted versioned registry (FOSS-445/447/449), import/overlay conflict handling (FOSS-437), advanced temporal constraints (FOSS-439), waiver authority (FOSS-443), profile/hybrid construction validation (FOSS-458), and complete threat-fixture runtime conformance (FOSS-459). No crates.io publication is enabled; the FOSS-466 GitHub administrator environment approval remains a separate blocker.
