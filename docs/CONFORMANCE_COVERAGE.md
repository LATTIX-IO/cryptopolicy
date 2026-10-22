# FOSS-459 — Normative conformance, runtime-binding increment A

## Existing and new evidence

The original 33-case `cryptopolicy.security-contract.v1` JSON corpus is a
**normative specification**, not the output of the evaluator. It remains
byte-for-byte unchanged and explicitly says `runtime_conformance_verified:
false`. The original static linter remains in place; no expected golden
output was regenerated or rewritten by CI.

This increment and the FOSS-492 core extension add:

- `tests/fixtures/conformance/runtime-coverage-v1.json`: all 33 IDs in
  normative order, anchored to the exact original Git blob content identity,
  with declared `runtime-subset` or substantive `pending` status.
- `crates/cryptopolicy/tests/normative_runtime.rs`: 22 direct Rust tests
  that load the **actual original normative corpus** and execute current
  policy evaluator or validation APIs with stable test fixtures.
- `scripts/conformance_coverage.py`: rejects missing/reordered cases,
  duplicate JSON keys, absent test symbols, unbound status promotions,
  unexpected normative bytes and any claim of full verification.
- CI invokes the Python crosswalk integrity suite and the real Rust
  integration suite on every PR and main push.

## Exactly what has runtime assertions

| Cases | Contract behavior |
|---|---|
| CASE-002 | No matching Allow means Deny/default-denied |
| CASE-003 | Explicit Deny defeats matching Allow |
| CASE-004 | Missing classification on potentially applicable Deny => Indeterminate |
| CASE-006 | Missing required key protection => Indeterminate |
| CASE-011 | Invalid rule-level UTC interval => policy validation failure |
| CASE-027 | Reordering matching Deny does not change decision/digest/reasons |
| CASE-032 | Reverse rule ordering preserves the complete Deny result |
| CASE-033 | Valid synthetic, caller-supplied observed/HSM fixture => Permit data record |
| CASE-001/005 | Missing default effect and invalid rule effect => parser errors (normative InvalidPolicy family) |
| CASE-012 | Legacy RSA deny activates at inclusive prohibited time; replay and rule ordering stable |
| CASE-022 | Pinned cyclic policy imports => typed CycleDetected |
| CASE-024 | Excess input bytes => typed PayloadTooLarge |
| CASE-025 | Excess policy dependency depth => typed ResourceLimit(import_depth) |
| CASE-014 | Unknown vendor AES alias => Indeterminate with UnsupportedProfile |
| CASE-016 | Installed dependency is not executed operation; missing operational evidence => Indeterminate |
| CASE-017 | Partial coverage and empty observations => Indeterminate (missing evidence) |
| CASE-018 | Configured TLS suite without negotiated session => Indeterminate (non-operational) |
| CASE-019 | HSM provider self-claim without independent attestation => Indeterminate |

The subset compares **actual outcome and presence of required controlling
reason codes**, not full exact ordered reason-vector identity for every case.
CASE-027 and CASE-032 additionally compare the complete deterministic
decision, and CASE-033 pins its full current runtime reason vector.
The `InvalidPolicy` expectation on CASE-011 is asserted against the
runtime `ContractError::InvalidDocument` variant, not an invented
exported error code.

`Permit` remains only a **data record**. The library does not authenticate
the issuer, evidence collector, claimed HSM assurance, TLS transcript,
signature or any downstream operation; these tests must not be interpreted
as a real access-control endorsement.

## Pending cases and dependencies

The other **11 cases remain explicitly pending**. Especially:

- CASE-008/009/010: now execute exact negative-path deny, tenant-scope and
  typed invalid-approval tests with blocked, redacted audit receipts. Positive
  signed-waiver admission still requires FOSS-503 and remains unverified.
- CASE-020/021: X.509/JOSE adapters have independent security tests, but
  their typed adapter errors are not mapped into the original generic
  normative error vocabulary.
- CASE-029: named hybrid TLS constraints are recognized by FOSS-458, but
  crosswalking a generic hybrid **policy document** into exact construction
  enforcement is not complete.
- CASE-028: actual downstream enforcement is outside the current Rust
  metadata library. The existing consumer test proves non-Permit does not
  authorize in that example, not comprehensive PEP enforcement.
- CASE-030/031: strict schema rejection and issuer strings versus verified
  policy authenticity require explicit error/trust boundary crosswalks.
- Remaining compositions, inventory/assessment/provider snapshots and
  privacy/redaction cases require scenario-exact runtime bindings.

Adapter source-specific test suites already exist:

| Source | Current executable suite |
|---|---|
| FIPS 203/204/205 algorithm catalog | `crates/pqc-kit/tests/catalog.rs` |
| X.509 RFC 9881 / RFC 9935 | `crates/pqc-x509/tests/identities.rs` |
| RFC 9964 JOSE/JWK ML-DSA | `crates/pqc-jose/tests/identities.rs` |
| RFC 9964 COSE ML-DSA | `crates/pqc-cose/tests/identities.rs` |
| RFC 10024 hybrid TLS | `crates/pqc-kit/tests/tls_hybrid.rs` |
| Policy temporal boundaries | `crates/cryptopolicy/tests/temporal.rs` |

Passing those suites does NOT automatically mark a specification case
`runtime-subset` until the exact normative scenario and expected reason/
error vocabulary are linked to real library outputs.

## Reproduce

    python3 scripts/security_contract.py --lint
    python3 scripts/conformance_coverage.py
    python3 -m unittest discover -s tests -p test_conformance_coverage.py -v
    cargo test -p cryptopolicy --test normative_runtime --locked
    cargo test --workspace --all-features --locked

**Release status:** This is increment A of FOSS-459, not complete runtime
conformance. The full 33-case result comparator must not be marked
operationally verified until all 33 cases have proven runtime bindings,
the missing exception/enforcement scopes are supplied, independent
goldens are audited, and complete reason/error output is checked. Source
crate manifests continue to say `publish = false`; FOSS-464/466 remain
release authorization gates.

### FOSS-492 residual normative mismatch (not covered)

CASE-007 and CASE-023 require **compile-time** PolicyConflict for attempted baseline weakening or contradictory exact profile constraints. The current composition model is a conjunction of independently evaluated layers; it prevents unauthorized use but does not always return that normative *error family* at compilation. CASE-030 expects UnsupportedSchema for unknown critical fields, while serde currently returns InvalidJson (fail closed, different error code). CASE-031 expects InvalidPolicy for untrusted issuer authentication; the policy DTO parses unverified issuer strings and leaves actual provenance authentication outside its API. None of these four may be marked runtime-subset without an explicit source-verified API and reason/error crosswalk. These are retained for FOSS-492/B.

Current binding total after FOSS-501/A: **22/33**; remaining **11**. Normative file and `runtime_conformance_verified=false` remain untouched. Actual Rust error variants are checked before mapping expected abstract normative error families; this is not a statement that the runtime already serializes the abstract codes.

### FOSS-493 source-evidence conformance distinctions

CASE-014, CASE-016, CASE-017, CASE-018 and CASE-019 are directly runtime-linked under FOSS-493/A. Where the assessment/provider APIs have more specific reason types than the original normative corpus, the production `cryptopolicy::normative_projection` functions conservatively map *only* an Indeterminate result plus explicitly missing evidence/coverage/assurance to `ReasonCode::MissingRequiredAttribute`. These functions never return a Permit or authenticate sources. The tests validate both actual report status and the typed non-authorizing projection, not simply an expected fixture echo.

The remaining FOSS-493 cases **CASE-013, CASE-015, CASE-020, CASE-021 and CASE-029** are deliberately pending. CASE-013 needs exact SecurityCategoryInsufficient semantics distinct from a catalog downgrade marker. CASE-015 names a draft-composite experimental construction that is not present in the currently pinned standards catalog, so mapping some other experimental profile would be false equivalence. CASE-020/021 require exact normative error vocabulary projection tied to real X.509/JOSE parsers and source-specific critical metadata. CASE-029's generic hybrid flag has no typed policy-construction admission DTO; generic JSON rejection cannot prove the specific normative contract. Follow-on FOSS-493/B must deliver these without changing the original normative goldens or inventing validation authority.

Automated review identified that the earlier CASE-019 test stopped at source authentication and could not exercise missing attestation. The revised test independently authenticates a synthetic source binding but withholds HSM assurance verification; the actual capability report must return Indeterminate with AssuranceNotVerified. The generic hybrid malformed-input regression remains executed but is **not** claimed as CASE-029 conformance.

### FOSS-501/A negative-only authenticated-exception evidence

Three additional existing normative cases have real, source-linked Rust tests:
CASE-008 executes a matching legacy-RSA explicit Deny after the exact
2026-01-01 exception-expiry boundary at 2026-10-16 UTC; CASE-009 attempts
a tenant-a waiver against tenant-b; CASE-010 passes an unverified approver
and absent approval evidence into a new typed validation boundary returning
`ExceptionAuditError::InvalidException`. All three assert their original
independently pinned normative result and block enforcement. For CASE-008
and 009, `build_blocked_exception_audit_receipt` constructs the complete
bounded, deterministic, **non-authorizing** fingerprinted audit from actual
`WaiverAdmissionReport` and E0 structural evaluation, excluding original
raw fact/evidence payloads. This does NOT prove a valid signed waiver, a
production KMS/PDP trust integration, or positive admission. No expected
values in the 33-case normative JSON were modified.

### FOSS-494 — Privacy and test-consumer regressions (not normative promotion)

PR #37 adds two bounded negative regressions using the real parser/evaluator
and an explicitly test-only consumer. Both cases remain pending:

- CASE-026: An invalid `not-allowed` operation carrying unrecognized
  `private_key_material` and `subject_token` fields fails with a strict
  `ContractError::InvalidJson` without echoing the secret values. A
  **different**, valid deny-by-default request does not reflect its issuer
  subject or request ID in serialized decision or Debug output. This is
  not the exact normative scenario's Deny/DefaultDenied result. A reviewed
  inbound adapter and safe diagnostic projection are required.
- CASE-028: The synthetic callback consumer uses real evaluator results
  and parser failures and skips the closure on Deny, Indeterminate or Error.
  It is not a shipped, source-authenticated downstream PEP or proof that
  a real application cannot continue after a non-Permit decision.

The normal `PolicyDecision` includes caller-controlled `RuleId` and
`EvidenceId` strings and must not be logged as universally sanitized.
Neither this library nor these tests authenticate an issuer or execute
a protected cryptographic operation. Hypothetical waivers are not permits.

Original CASE-008/009/010 negative exception coverage remains unchanged.
The normative 33-case contract and pinned blob identity are unmodified.
Runtime-subset coverage stays **22/33 with 11 pending**. This PR is
intermediate regression hardening, not FOSS-494 or FOSS-459 closeout.
Five source crates remain `publish = false`.

### FOSS-514 — Exact typed UnsupportedSchema CASE-030 admission

The new `parse_policy_for_admission_with_limits` checks bounded inputs
against the existing strict parser **first** and never admits a document
that the legacy parser rejects. Only after a strict-parser failure does a
separately bounded root-vocabulary/schema-version inspection classify
unknown top-level security-critical fields as `PolicyAdmissionError::UnsupportedSchema`.

The runtime test `case_030_unknown_critical_policy_field_is_unsupported_schema`
adds the original normative `override_deny_silently: true` field to a valid
policy fixture, observes an exact UnsupportedSchema result from the shipped
API, verifies the unchanged original parser still rejects the same bytes,
then directly asserts the pinned original CASE-030 error family.

Malformed/nested policy inputs remain non-authorizing `InvalidPolicy`,
and resource exhaustion yields `ResourceLimit`. All typed diagnostics omit
attacker-controlled source strings. This error projection does not attest
policy issuers, evaluate requests or operate an enforcement point.

Normative fixture contents, original golden expectations, declared
`complete_normative_conformance=false`, and blob identity remain unchanged.
**Current runtime-subset coverage: 23 of 33; 10 cases pending.**
CASE-007/023/031 remain in FOSS-496; CASE-026/028 remain in FOSS-494.
FOSS-495 full 33-case conformance is still blocked. Source crates stay
unpublished. See [schema admission](SCHEMA_ADMISSION.md).
