# FOSS-501/A — Blocked exception audit and three normative cases

## Intent

This is a deterministic, **negative-only** audit surface over an already
evaluated immutable policy decision. It does not authenticate signatures,
approve waived Deny/Require rules, grant a production Permit, or carry an
enforcement credential. All consumers must block the proposed operation
unless they independently obtain and authenticate authorization elsewhere.

The `build_blocked_exception_audit_receipt` function takes the real
`WaiverAdmissionReport` from FOSS-500/A, an exact E0
`ExceptionReference`, its bound context, and explicit resource limits.
It requires the original whole-graph outcome to be **Deny**, the candidate
to be non-Permit with no simulated target layer, the original policy
digest and injected UTC time to match, and an actual explicit Deny reason
for the exact targeted policy and RuleId.

The receipt contains only version, pinned effective/policy digests,
exception ID and correlation digest, targeted RuleId, bounded
compensating rule IDs, explicit UTC time, original/candidate outcomes,
rejection disposition, structural E0 finding, exact typed blocking
reasons and a `Block` enforcement classification. It never serializes
untrusted issuer strings, source/approval handles, raw facts, policy
justification, attestation secrets, key material, credential bytes or
signature contents. Every source reason is computed from the actual
original `EffectiveDecision`; no caller-supplied expected result is
echoed into the receipt.

`BlockedExceptionAuditReceipt::correlation_digest` is a deterministic
domain-separated SHA-256 content fingerprint with a length prefix. It is
**not** an HMAC, digital signature, proof of custody, event immutability
under a trusted log, revocation check or policy attestation.

The typed `validate_verified_exception_reference` function parses
actual closed E0 JSON and checks the injected bound context using the
supplied external `ExceptionSourceVerifier`. Missing approval evidence,
a mere `approver="unverified-string"`, forged scope, unknown fields,
invalid issuer or an untrusted source return `ExceptionAuditError::InvalidException`;
they do not produce an authorized reference or untrusted text error.

## Normative negative cases — directly executed

- **CASE-008:** Matching explicit Deny for legacy RSA under a pinned
  source policy. The exception expired at **2026-01-01T00:00:00Z**;
  evaluation is **2026-10-16T00:00:00Z**. Actual E0 finding is
  `Expired`; original `PolicyDecision` is Deny/ExplicitDeny, receipt
  enforcement is Block.
- **CASE-009:** Matching explicit Deny, exception scoped to tenant-a
  but independently bound request scoped to tenant-b. Actual finding is
  `OutOfScope`, Deny/ExplicitDeny remains, receipt says Block.
- **CASE-010:** Actual closed-schema parsing of an unverified approver
  with null approval evidence produces typed `InvalidException`.
  A syntactically valid but unverified approval reference also fails.

The canonical 33-case `cryptopolicy.security-contract.v1` expected
fixture is unchanged. The runtime crosswalk goes **19/33 to 22/33**:
three new exact tests, **11 pending**. This is partial, not complete
normative conformance.

## Reproduction

    cargo test -p cryptopolicy --test normative_runtime --locked
    python3 scripts/conformance_coverage.py
    python3 -m unittest discover -s tests -p test_conformance_coverage.py -v
    cargo test --workspace --all-features --locked

The audit API is intentionally limited to the negative security corpus;
a successful approved waiver requires FOSS-503's catalog-aware,
source-authenticated named-profile evaluator, completed FOSS-502, and a
separately reviewed positive signed audit/PEP enforcement contract.
No crate manifests or protected publish environment were changed;
FOSS-464 and FOSS-466 govern eventual crates.io publication.
