# FOSS-500/A — Exact-scope simulated Deny waiver admission

## Runtime boundary

FOSS-499 E0 provides reference parsing, exact scope/time verification and
**non-authorizing** admission-readiness metadata. FOSS-500/A introduces a
separate, *hypothetical* policy-owner-admitted evaluation for one precisely
targeted, original explicit Deny rule. This API does **not** issue signed
authorization tokens, authenticate approval signatures, or enforce an
operation. It cannot alter the source compiled `EffectivePolicy`.

Use `evaluate_deny_waiver_candidate` with an immutable precompiled
`EffectivePolicy`, a caller-supplied `CryptoContext`, the separately
authenticated `ExceptionScope` (including actual tenant and key reference),
explicit `EvaluationTime`, an exact `ExceptionReference`, a separate
`PolicyWaiverGrant`, both independent verifier callbacks and resource
limits.

An E1 grant includes the original pinned policy ID/version/digest, target
RuleId, E0 exception ID/correlation digest, exact scope, independent policy
owner approval reference, deviation type, sorted compensating requirement rule
IDs, and inclusive authorization/exclusive expiry timestamps. It is an
**untrusted DTO** until the consuming caller independently authenticates the
policy-owner grant. The default `UnverifiedPolicyWaiverAuthority` rejects
approval. No unsigned owner/approver field or digest authenticates itself.

## Fail-closed pipeline

1. Validate the caller's `Limits` and both closed DTO structures.
2. Evaluate the *unchanged* compiled policy graph against the exact injected
   timestamp. The result is preserved verbatim in the report.
3. Require exact equality for request operation, environment, algorithm,
   single fact and explicitly supplied tenant/key scope. Until FOSS-502 adds an
   independently verified exact-profile binding, any non-null cryptographic
   profile is rejected as `ScopeMismatch`, rather than inheriting an
   algorithm-only waiver. Original context
   intentionally does not include a trusted key owner: the consumer MUST bind
   `ExceptionScope.key_ref` to its actual target key externally.
4. Locate the exact pinned policy node and verify that its targeted rule is
   an explicit Deny that *actually matched* the original runtime decision.
   No policy-expiry or previously unsupported/default Deny can be waived.
5. Run E0 exact scope/status/time preflight and its independent external
   source, approver, approval proof and revocation verifier. All four are
   mandatory. E0 reference readiness is **not sufficient** for this step.
6. Compare the grant's pinned policy, rule, exception ID/correlation digest,
   scope, deviation, compensators and valid time. Require independent policy
   owner authorization from a **different verifier interface** with exact
   policy ownership/delegation/revocation check. Missing any proof rejects.
7. Require every compensator to name a nonempty `Require` rule in the exact
   target policy. Construct only a local clone of that policy and remove only
   the named, independently approved explicit Deny. Re-run the real
   `evaluate_with_limits` engine against the cloned policy. Every mandatory
   compensator must have an exact `RequirementSatisfied` reason.
8. Recombine with the **original** decisions of every unrelated policy
   layer, preserving Deny > Indeterminate > Permit. An unrelated Deny or
   uncertain mandatory requirement cannot be waived.

The result contains the original `EffectiveDecision` and original effective
digest unchanged, a disposition, candidate outcome, and optionally a
hypothetical target-layer decision whose **new digest is visibly distinct**
from the source policy reference. The report must not be presented as a
normal signed `PolicyDecision` or policy grant. A simulated
`candidate_outcome=permit` is not an authorization to execute cryptography.
External authorization/enforcement may require additional controls.

## Regression/security suite

`cargo test -p cryptopolicy --test exception_admission --locked`

The test suite exercises: explicit matched Deny removed only under two test
verifiers; default reject-all for each verifier; owner/approval/key/tenant
binding mutations; inclusive/exclusive time; revoked/suspended source;
missing and failed compensator; other mandatory baseline Deny dominance;
unmatched Deny; rule reordering; stable original/simulated fingerprints;
strict grant unknown fields, duplicates and JSON size bounds. Both positive
verifiers are fixed **synthetic test stubs**, not valid production signing or
policy-delegation mechanisms.

## Explicitly deferred

- `ExceptionDeviation::RuleRequirement` is **not supported** by this
  increment and is rejected rather than silently weakening a mandatory
  requirement. FOSS-500/B must independently design exact rule-waivability,
  cross-policy mandatory constraints and origin authentication.
- The present E1/A grant does not serialize or verify cryptographic
  signatures. FOSS-500/B and production callers must provide authenticated
  issuer/public-key trust and revocation policy in the external verifier.
- E2 / FOSS-501 must supply full immutable exception audit receipts and
  exact runtime normative CASE-008, CASE-009 and CASE-010. FOSS-494/495
  remain incomplete.
- The FOSS-459 33-case normative conformance manifest remains unchanged;
  this PR **does not** claim new normative cases.
- All crates retain `publish = false`; FOSS-464 and FOSS-466 remain
  separate controlled-release gates.
