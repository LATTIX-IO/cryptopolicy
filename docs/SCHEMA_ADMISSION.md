# FOSS-514 — Fail-closed policy schema admission (CASE-030)

## Purpose

`parse_policy_for_admission_with_limits` is an optional strict policy
admission entrypoint for untrusted JSON. On **success**, it returns exactly
the `PolicyDocument` accepted by the unchanged
`PolicyDocument::parse_json_with_limits` implementation. On failure, it
projects a stable, payload-free, non-authorizing error family:

| Error | Meaning |
|---|---|
| `UnsupportedSchema` | An unknown v1 **top-level** policy field or an unsupported explicitly declared schema version was present in otherwise parseable JSON |
| `InvalidPolicy` | Malformed JSON, missing required field, invalid nested policy or unsupported policy semantics not covered by the top-level schema classifier |
| `ResourceLimit` | Byte/depth/resource limit was invalid or exceeded |

An `UnsupportedSchema` error is only classified after the normal strict
parser failed. A bounded second JSON read inspects the root vocabulary
and declared schema version; this never permits a rejected document.
No parser error strings, raw JSON, unknown field names, issuer subjects
or secrets are exposed through the typed error.

## Example

```rust
use cryptopolicy::{parse_policy_for_admission, PolicyAdmissionError};

let request = br#"{\"schema_version\":\"1\",\"override_deny_silently\":true}"#;
assert_eq!(
    parse_policy_for_admission(request),
    Err(PolicyAdmissionError::UnsupportedSchema)
);
```

This example is intentionally incomplete policy JSON; it illustrates a
schema-classification failure, not a successfully evaluated policy.
See the `schema_admission` test suite and the CASE-030 normative runtime test
for a complete policy carrying the same injected critical field.

## Trust and compatibility

- Existing `PolicyDocument::parse_json` and normal evaluator semantics stay
  unchanged. The legacy strict parser continues to return `InvalidJson`
  for unrecognized JSON fields.
- `UnsupportedSchema` covers unknown **root-level** keys and explicitly
  unsupported schema versions, not every possible malformed nested object.
  Nested fields are still rejected, with `InvalidPolicy` for this adapter.
- No issuer verification, signer authentication, cryptographic operation,
  PDP/PEP permit or policy waiver is produced by this API.
- Outputs are deterministic for the same bounded input and all failures
  remain non-authorizing. Caller-provided policy/evidence identifiers may
  still carry sensitive strings in other public data contracts; do not log
  unreviewed policy/decision DTOs.

## Normative coverage

Exact source CASE-030 is linked to
`case_030_unknown_critical_policy_field_is_unsupported_schema`, exercising
the actual exported API against `override_deny_silently` and asserting the
normative `UnsupportedSchema` error. The checked-in original 33-case
normative fixture and its Git blob pin are unmodified. Coverage is
**23/33 runtime-subset and 10 pending**; complete conformance remains false.

FOSS-496 still owes CASE-007/023/031; FOSS-494 still owes CASE-026/028.
All five crates remain unpublished.
