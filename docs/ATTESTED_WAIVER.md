# FOSS-508 — Source-qualified, exact-scope hypothetical waiver

## Security boundary

The opt-in `evaluate_attested_waiver_candidate` API is a **non-authorizing
policy-data simulation**. It never signs an approval, grants an enforcement
credential, controls a PEP or KMS, performs a cryptographic operation, or
modifies the original compiled `EffectivePolicy`.

A report carrying `WaiverAdmissionDisposition::CandidateEvaluated` and
`candidate_outcome = Permit` is **NOT** permission to execute cryptography.
Both fields are ordinary inspectable Rust data. The consuming application must
independently authenticate the policy issuer and handle enforcement and key
authorization through its trusted PDP/PEP. Historical original Deny or
Indeterminate decisions remain available in the same report.

## Executed trust chain

Every call constructs a fresh `ReviewedWaiverRequest` and first invokes
`evaluate_reviewed_waiver_candidate`. It must pass **all** existing FOSS-502
gates to reach the deliberate `ProfileEvaluatorUnsupported` disposition:

1. Real target operation, environment, algorithm, tenant and key scope equality,
   and exact observed named profile.
2. Independently verified current key owner and key generation.
3. Active owner-controlled policy-pinned waivability registry, signed source,
   owner delegation, current revocation, monotonic revision and nonce freshness.
4. Exact E0 exception ID, rule, digest, approval evidence, authorized approver,
   revocation state and time.
5. Separate exact E1 policy-owner grant, approval scope, deviation, compensators
   and explicit validity interval.

The trust callbacks are caller-owned and can be faulty. None of the embedded
identifiers, JSON metadata, `verified=true`, hash fingerprints, claimed policy
issuers or synthetic test callbacks authenticate themselves.

After these checks, the function confirms that the **original** source
`EffectiveDecision`, evaluated from the immutable compiled graph, contains a
matched, blocking `ExplicitDeny` or failed/unknown mandatory `Require` for
the exact target `PolicyReference` and `RuleId`. An unmatched Deny, default
Deny or policy expiry is not a waiver target. A rule in a different policy
with the same RuleId is not equivalent.

Only a separately approved `RuleDeny` or `RuleRequirement` is eligible.
Every approved compensator must be an independent, nonempty `Require` in
the original target policy. The engine copies *one* target policy, removes
*one* original blocking rule, and calls FOSS-507
`evaluate_qualified_profile_with_limits` on that derived document using the
unchanged original `CryptoContext`, exact real key/profile scope, typed
parameter witness, explicit UTC time and independent source/key callbacks.
That re-executes the pinned FOSS-445 catalog qualification on **every** call.

A candidate can be considered only if the qualified result is Ready, its
actual target decision is Permit, and **every** mandatory compensating RuleId
is independently present in `matched_rules` with
`ReasonCode::RequirementSatisfied`. Unsupported named hybrid constructions,
unknown/draft/aliased profiles, stale KMS attestations, missing evidence or
unsatisfied compensation never produce a candidate Permit.

The original target policy and its pinned SHA-256 digest are never changed.
The derived target decision must have a distinct digest. The aggregate
hypothetical result combines that one candidate layer with the untouched
**original** results from all other baseline, overlay and imported policies:
Deny dominates Indeterminate, which dominates Permit. Other policy layers
are *never* reinterpreted as approved by a waiver.

## Explicit limitations

- A caller-supplied verifier is trusted to authenticate original signed
  source/provider evidence and all policy-relevant fact fields, not merely
  attest an `evidence_ref` string.
- Registry nonce monotonicity and signer revocation require real durable
  caller-owned state. This pure library does not persist state or look up keys.
- The library does not authenticate policy authors or issue an enforceable
  authorization token. Production trust must be provided separately.
- The existing legacy `evaluate_with_limits`, FOSS-500/A profile-less
  `evaluate_deny_waiver_candidate`, and FOSS-502 fail-closed reviewed API
  remain unchanged.
- Negative-only FOSS-504 `BlockedExceptionAuditReceipt` builders cannot
  fingerprint a hypothetical positive waiver. Positive signed audit and
  actual PDP/PEP integration require separately reviewed design.
- No additional FOSS-459 normative goldens are claimed. Corpus remains
  partially bound at 22 of 33 cases. Publishing remains disabled for all
  five crates; FOSS-464 and FOSS-466 govern any later release.

## Reproduction

```sh
cargo test -p cryptopolicy --test attested_waiver --locked
cargo test -p cryptopolicy --test profile_qualification --locked
cargo test -p cryptopolicy --test waivability --locked
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
```

The synthetic test verifiers are fixtures, **not** usable trust anchors or
production credentials. Negative tests require failures for missing E0/E1
proof, stale/replayed registry or key, wrong tenant/operation/profile, expired
exception or policy, unsatisfied compensating controls, unmatched rule and
an unrelated mandatory baseline Deny. Deterministic reruns must reproduce
both the candidate result and unchanged original decision/digest.
