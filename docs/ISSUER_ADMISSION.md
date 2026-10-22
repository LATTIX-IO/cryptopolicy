# FOSS-515: Issuer provenance admission (CASE-031)

## Purpose and normative trust boundary

`PolicyDocument.issuer.subject` and its optional `assurance_ref` are
untrusted metadata. Parsing a valid policy, matching an issuer name, or holding
an opaque assurance reference does not authenticate a signer or issue a
permission. The immutable CASE-031 contract requires **InvalidPolicy / block**
when the input claims issuer `trusted-org` but caller-side trust validation
is absent.

This increment adds a separate **opt-in** `admit_policy_issuer` and
`admit_policy_issuer_json` API. The ordinary pure `evaluate` and strict
`PolicyDocument` parser remain unchanged. Default
`UnverifiedPolicyIssuerSource` always rejects.

## Exact bindings

The caller supplies a policy, independently pinned `PolicyReference` (ID,
version and canonical digest), an untrusted `IssuerProvenanceClaim`, an
independently supplied `IssuerAdmissionScope` (tenant, operation and fresh
challenge), UTC millisecond time, and explicit `Limits`.

Admission checks, before invoking the external verifier:

- Policy structural validity, bounded canonical digest and exact pinned
  identity; all mismatches reject, including a later modified issuer.
- Non-empty claimed source assurance reference identical to the policy's
  `assurance_ref`, plus exact issuer name. Neither constitutes trust.
- Exact proof policy reference, tenant, operation and freshness challenge.
- Explicit issuance, activation and exclusive expiry bounds for policy and
  claim, with no wall-clock inference.
- Bounded typed proof JSON. Parse failures remain
  `PolicyAdmissionError::InvalidPolicy` or `UnsupportedSchema`; resource
  failures become `ResourceLimit`, without copying sensitive input.

Only after those checks does `PolicyIssuerSourceVerifier::verify` run.
It receives the full original policy, trusted re-computed digest and exact
claim/scope/time. On **every request** it MUST independently verify the
source signature and certificate/key identity, current signer trust and
revocation, policy-owner authority or delegation, exact policy binding,
actual tenant and operation, and replay resistance across challenges and
grants. Integrations must keep replay state in a trusted store. The library
deliberately performs no signature verification or persistent replay tracking.

The verifier's answer is a **caller-owned trust assertion**; a malicious
accept-all implementation breaks the integration's security boundary.
A successful call returns only a non-serializable
`IssuerProvenanceAssessment` (pinned policy reference and checked-at time).
It is NOT an authenticated bearer token, cryptographic Permit, KMS grant,
PEP decision, waiver or authorization to perform the requested operation.

## Developer quickstart

```bash
cargo run -p cryptopolicy --example issuer_admission --locked
cargo test -p cryptopolicy --test issuer_admission --locked
cargo test -p cryptopolicy --test normative_runtime --locked case_031
```

The example passes complete valid policy JSON but deliberately uses the
reject-all verifier. Expected behavior is `InvalidPolicy` with no
protected operation performed. See `tests/issuer_admission.rs` for an
explicitly **synthetic, test-only** source verifier that checks exact fields,
simulates revoked attestations and rejects reused grant/challenge references.
It does not establish a production trust root.

## Security and compatibility tests

The negative suite checks unverified or absent evidence, forged issuer,
mismatched ID/version/digest, wrong tenant, operation and challenge, forged
owner/key/delegation/grant, revoked signer, expired windows, replay,
malformed JSON, unexpected security-critical fields, duplicate root fields,
bounded resources and generic nonreflection of sensitive invalid-input
values. A positive synthetic assessment also demonstrates that an ordinary
explicit Deny still takes precedence in policy evaluation.

The normative `case_031_issuer_string_without_source_verification_is_invalid_policy`
test reads the original CASE-031 input and expectation and evaluates the
real exported admission API with a reject-all independent verifier. Only this
specific case is added to the partial crosswalk: **24/33 runtime-linked,
9 pending**, subject to exact-head validation.

The checked-in 33-case normative corpus, its pinned blob SHA and
`complete_normative_conformance=false` are not modified. FOSS-496 continues
with CASE-007 and CASE-023; FOSS-494 continues with CASE-026 and CASE-028;
FOSS-495 retains the golden-output release gate. All five source crates remain
`publish = false`.
