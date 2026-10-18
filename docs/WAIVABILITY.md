# FOSS-502 — Externally reviewed waivability and named key/profile binding

This is a **non-authorizing, offline policy simulation**. The crate does not
validate signatures, query a KMS, establish tenant/key ownership or approve
exceptions. A candidate with `candidate_outcome=Permit` is not an authenticated
authorization token and must never be used as an enforcement decision.

## Why a second admission boundary is required

FOSS-499's strict exception reference and FOSS-500/A's separately approved
policy-owner grant are not, by themselves, proof that the pinned policy owner
designated a particular **rule and named profile as waivable**. The E1/A
`evaluate_deny_waiver_candidate` intentionally refuses any request whose
cryptographic fact carries a profile ID.

FOSS-502 introduces `evaluate_reviewed_waiver_candidate`, which requires
four caller-owned trust checks rather than simply reading asserted metadata:

1. **E0 approval provenance:** `ExceptionSourceVerifier` authenticates
   source, independent approver delegation, evidence and revocation.
2. **E1 policy-owner grant:** `PolicyWaiverAuthorityVerifier` authenticates
   the exact policy owner grant for its scope/target.
3. **Owner waiver registry:** `WaivabilityRegistryVerifier` independently
   authenticates the original registry bytes and owner delegation, current
   revocation, plus monotonic revision and replay nonce freshness.
4. **Actual key/profile ownership:** `KeyProfileBindingVerifier` checks the
   real key generation, tenant, cryptographic operation and exact named profile
   against the caller's independently trusted data plane.

All default implementations reject trust. A verifier implemented incorrectly
or configured to trust user-supplied booleans breaks that verifier's security
contract; the library never claims otherwise.

## Versioned owner registry and boundaries

`WaivabilityRegistry` is strict JSON with an exact PolicyReference
(ID/version/digest), one external signed-artifact ref, independent registry
identity, nonzero version/revision, anti-replay nonce, status, UTC
issued/effective/expires times and up to 16 sorted distinct target RuleIds.
Each `WaivableRuleEntry` pins one `ExceptionDeviation`, exact
tenant/environment/operation/algorithm/key scope, exact `ProfileId` and
nonempty sorted compensating `Require` rules. Registry membership alone
does not establish authenticity. Unknown fields, duplicate entries, invalid
ranges, missing compensation and oversized inputs fail closed.

`KeyProfileBinding` pins the same exact scope and profile plus an external
attestation ref and a key generation/version handle, all still untrusted
until the caller's own verifier authenticates them.

At a single injected `EvaluationTime`, the evaluator requires:

- An unchanged, pinned, resolved `EffectivePolicy` and one exact fact.
- Identical exception/grant/registry/source scopes and exact observed
  algorithm/profile; no fuzzy profile aliases or unbound profile promotion.
- Current Active registry and exact time-bounded owner approval.
- All registry authentication, owner delegation, revocation and replay flags.
- An actually matched named Deny or failed/unknown mandatory Require in the
  original target layer, subject to exact registry waivability.
- Independently satisfied nonempty compensating Require rules.
- Conjunctive preservation of every other baseline, overlay and import
  policy: Deny dominates Indeterminate, which dominates candidate Permit.

Only one *cloned* targeted policy is used for simulation. Its derived digest
is distinct from the source policy, and the original aggregate decision and
digest are never overwritten. The original FOSS-500/A legacy entrypoint
remains unchanged in its externally observable behavior.

## Intentional limitations

RuleRequirement deviations are supported **only** via the reviewed registry
entrypoint and only for a specifically blocked mandatory Require rule.
Unknown/missing requirements are never silently treated as satisfied:
the original blocking reason must identify that exact rule, other Require
rules continue to apply and independent compensation must pass. The API
does not attest the policy issuer itself; the external registry/approval
verifiers must validate the original owner delegation and policy source.
No signature or KMS integration is embedded into the Rust library.

A passed example test uses synthetic verifier functions and is **not a
production trust anchor**. The test suite includes stale revision/nonce,
revocation, forged registry/owner ref, missing source/verifier flags, exact
profile switching, key mismatch, duplicate/oversized/unknown registry,
false compensation, historical replay, and unrelated baseline Deny.

## Verify locally

    cargo test -p cryptopolicy --test waivability --locked
    cargo test -p cryptopolicy --test exception_admission --locked
    cargo test --workspace --all-features --locked
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

FOSS-501 will introduce immutable audit receipts and exact normative
CASE-008/009/010 runtime evidence. This increment **does not** modify the
original 33-case normative corpus or promote any case prematurely. Crate
manifests remain `publish=false` and publishing governance FOSS-464/466
is unchanged.
