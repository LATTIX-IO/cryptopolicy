# FOSS-499 / FOSS-443 E0 — Signed-reference exception metadata and trust gate

## Security model

An exception is a **request to deviate**, not authorization to deviate.
The `cryptopolicy` library neither creates cryptographic signatures nor
validates signers, key custody, approver delegation, revocation or policy
enforcement. The new E0 API has **no** mechanism for overriding any policy
rule, allowing an explicit Deny, or producing a `PolicyDecision::Permit`.

The v1 DTO has a strict, known-field, versioned JSON envelope containing:
an exception ID, exact `PolicyReference` (policy ID, semantic version and
canonical SHA-256 content digest), target `RuleId`, distinct owner and
approver IDs, original approval/source evidence references, deviation type,
nonempty independently enforced compensating rule references, justification,
claimed status, and explicit issued/effective/expiry UTC millisecond times.

Every exception has **exactly one** tenant ID, environment, operation,
algorithm ID and existing key reference; wildcards or unknown prefixes are
not accepted. This is narrower than generic tenant-level allow rules.
Compensating controls are nonempty, sorted, unique, bounded at 16 and cannot
reference the targeted rule itself. The reason is bounded at 512 UTF-8 bytes
and contains no control characters. Serialized input is capped at 16 KiB,
or a lower caller-configured maximum. Unknown schema members, duplicates,
unsupported enum variants, invalid identity grammar, invalid time ranges,
oversized data and unsupported wire versions fail closed.

The `ExceptionReference::correlation_digest()` result hashes the closed
canonicalized struct JSON with an explicit domain and length prefix; it is
**not a signature, MAC, provenance proof or signer identity**. Calling code
must authenticate original artifact bytes and handle out-of-band expiration
and revocation.

## Offline reference preflight

`assess_exception_reference(reference, bound_context, verifier)` performs
only the following bounded checks, in order:

1. Validate all DTO structural invariants.
2. Reject Revoked and Suspended records without consulting a verifier.
3. Compare exact policy ID/version/digest, targeted rule, tenant, environment,
   cryptographic operation, algorithm and key reference.
4. Enforce inclusive `effective_at` and exclusive `expires_at`, using
   the caller-injected `EvaluationTime`. No hidden system clock.
5. Invoke the caller-supplied `ExceptionSourceVerifier` only if every
   preceding check succeeds. Require all four *independent* fields:
   `source_authenticated`, `approver_authorized`, `approval_verified`
   and `revocation_checked`.
6. Return `ReferenceReadyForPolicyAdmission` only when the caller's verifier
   reports every check. This indicates a claim of readiness for future
   separately governed policy admission, **not** approval to waive a Deny,
   an authenticated decision or any cryptographic operation.

`UnverifiedExceptionReferences` supplies the safe default; it always
produces the nonauthorizing Unverified finding for an otherwise applicable
record. A malicious or incorrectly implemented verifier can lie: no
in-process status code can substitute for the caller's own security-reviewed
cryptographic verification and trusted policy admission.

The `ExceptionReferenceReport` contains only exception ID, correlation
digest, the injected time, finding and reported verification flags. It
contains no raw signature, user credentials, key bytes or personal content.
Proof records should be held and governed by the consuming application.

## Reproduction

    cargo run -p cryptopolicy --example exception_reference
    cargo test -p cryptopolicy --test exception_reference --locked
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo test --workspace --all-features --locked

The synthetic fixture in
`crates/cryptopolicy/tests/fixtures/exception-reference-v1.json` is a
schema example, not an actual signed approval. The test-only verifier
authenticates deliberately fixed fixture handles; production cannot rely
on this stand-in. The tests cover default rejection, each trust bit
independently, synthetic ready status, exact scope components, wrong pinned
digest/rule, revoked/suspended status, time boundaries, missing attributes,
oversized resource inputs, duplicate/unknown JSON, nonunique/unsorted
compensation and deterministic fingerprints.

## Deferred and explicitly unsupported

- **FOSS-500 / E1:** Policy-owner rule-waivability permissions, approved
  deviation admission, detailed scoped compensating evaluation and
  non-weakening of mandatory baseline/overlay controls.
- **FOSS-501 / E2:** Exact audited exception-decision receipts and runtime
  normative security CASE-008/009/010 integration.
- **FOSS-494:** Remaining exception, redaction and PEP enforcement corpus.
- **FOSS-495:** Complete 33-case normative runtime conformance.

This PR does **not** update the FOSS-459 normative conformance coverage
manifest or claim any additional normative cases. The existing corpus stays
specification-only. All five crates remain `publish = false`; FOSS-464/466
are separate authorized-release requirements.
