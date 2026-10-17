# Cryptopolicy v1 — typed selectors and static policy validation

**Issue:** FOSS-434. **Status:** Implemented static contract and tests; **no runtime evaluator**. The next FOSS-435 increment will interpret rules for an actual request and return a PolicyDecision. Static success must never be treated as an authorization.

## Contract boundary

All predicate fields are exact typed comparisons composed by logical AND. Existing selectors retain the v1 keys `match_all`, `operation`, `algorithm_id`, `profile_id`, and `environment`. The optional nested `advanced` object supports:

| Field | Type | Security meaning |
|---|---|---|
| security_category | integer in 1..=5 | Exact declared security class, not an algorithm assessment |
| data_sensitivity | public/internal/confidential/restricted | Caller-defined classification, not verified authority |
| provider_id | ProviderId | Exact ASCII-safe provider identity |
| key_protection | software/hardware_backed/hardware_security_module | Claimed protection class, not cryptographic attestation |
| key_exportable | boolean | Explicit key exportability, not inferred |
| key_size_bits | 1..=1,048,576 | Generic hard validation cap, not per-algorithm feasibility |
| source_origin | requested/configured/negotiated/observed/inferred/provider_capability | Origin preserved without aliasing configured to observed |
| source_quality | unverified/attributed/externally_verified | Declared quality; authentication and trust are external |

The optional `CryptoFact.properties` carries the corresponding typed claims. The optional `CryptoContext.environment` identifies a caller environment. Each new field uses `#[serde(default, skip_serializing_if = "Option::is_none")]`; existing v1 fixtures and canonical policy digests therefore remain unchanged when the fields are absent. Unknown/unsupported nested fields or enum variants are rejected. Requirement decoding uses a strict two-field envelope: a recognized variant cannot ignore an unknown sibling key, duplicate key, unexpected unit payload or missing value.

No arbitrary scripting, regex, code execution or implicit selector aliases exist. The `advanced` object may not be empty; `match_all=true` may not be combined with any other predicate. An explicit `match_all` with a Require effect is permitted only when mandatory requirements are provided. Allow rules must identify an exact algorithm or named profile using a selector or mandatory requirement; a blanket Allow is statically rejected.

## Typed mandatory requirements

The existing `algorithm`, `profile`, `min_security_category`, `non_exportable` and `named_hybrid` requirements remain supported. Added types: `provider`, `sensitivity`, `key_protection`, `key_exportable`, `source_origin`, `source_quality`, `key_size_bits` and `minimum_key_bits`. Within a rule these are conjunctive conditions, never alternative matches.

The analyzer rejects incompatible exact requirements, e.g. two different algorithms, profiles/hybrid construction names, provider IDs, sensitivity/protection classifications, quality/origin or exportability. It also rejects contradictions between selectors and corresponding requirements, including exact key bits lower than a declared minimum or a declared category lower than the requirement. Generic key bit bounds are not approval of a real cryptographic implementation: exact key/profile feasibility and standards status are owned by FOSS-445.

## Missing-fact behavior contract for FOSS-435

| Effect / condition | Missing fact disposition | Can this establish Permit? |
|---|---|---|
| Allow selector | NonMatch | No |
| Warn selector | NonMatch | No |
| Deny selector (potentially applicable) | Indeterminate | No |
| Require selector (potentially applicable) | Indeterminate | No |
| Any mandatory requirement | Indeterminate | No |

This table is exposed through `missing_selector_fact(effect)` and `missing_required_fact()`. It is a future evaluator contract, **not** an implementation of selector matching. The future evaluator must preserve Deny precedence, prevent unknown profiles from authorizing and distinguish definitive denial from missing potentially decisive facts.

## Static diagnostics

`PolicyDocument::static_validate()` returns a `ValidationReport` with a v1 schema, stable `ValidationCode` identifiers, `Error` or `Warning` severity, and optionally a RuleId. Results are ordered by RuleId then code/severity irrespective of input order. Diagnostics never contain raw credentials, algorithm values, issuer strings, key material or request context.

An error blocks `PolicyDocument::validate()`, strict JSON parsing and canonical serialization. Warnings do not authorize anything. For compatibility, a deliberately authored `default_effect=allow` is a warning rather than an automatic Permit; FOSS-435 must not grant a default Permit. Existing Deny rules with requirements produce a warning stating that requirements cannot soften Deny; a future evaluator must treat a matching Deny as unconditional. Warn rules with mandatory requirements are rejected until their semantics can be defined unambiguously.

`static_validate_with_limits(limits)` enforces FOSS-433 rule, per-rule requirement, metadata and diagnostic budgets. An excess returns `ResourceLimitExceeded`, never a partial/truncated successful report. The parser also validates context field ranges and catches contradictions in declared quality flags.

## Reproduction

```sh
cargo run -p cryptopolicy --example static_policy
cargo test -p cryptopolicy --test static_validation --locked
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

The versioned fixture lives at `crates/cryptopolicy/tests/fixtures/static-policy-v1.json`. It exercises all 12 selector fields, typed requirements, Allow/Deny/Require/Warn effects and a no-error validation outcome. The example then deliberately introduces conflicting algorithm requirements, producing the stable `conflicting_algorithm` error without executing policy rules.

## Security and remaining tasks

- **No runtime authorizations:** There is still no `evaluate(policy,context,...)` in this increment.
- **No source attestation:** Evidence quality, `verified` flags, provider protection and issuer data are untrusted claims until independently authenticated (FOSS-447/449).
- **No standards registry:** Unknown or experimental algorithm identifiers cannot be deemed approved; profile classification and algorithm-specific constraints belong to FOSS-445.
- **No composite/temporal/waiver logic:** FOSS-437/439/443/458 own composition, time-bounded decisions and exceptions.
- **No crates.io publication:** All bootstrap manifests remain `publish=false`, with FOSS-466 administrative approval still outstanding.
