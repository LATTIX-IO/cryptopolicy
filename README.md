# cryptopolicy

Policy-driven cryptographic agility and post-quantum integration.

Maintained by Lattix Technologies Corp.

Project website: https://lattix.io

## Status

This project is in early development.

Public APIs should be considered unstable until the relevant crates reach
their first stable release.

## Security contract (pre-implementation)

The [threat model](THREAT_MODEL.md) specifies fail-closed decision rules,
trust boundaries and 33 versioned golden security-contract cases. FOSS-435 now
provides a conservative, executable single-context evaluator and dedicated
truth-table regression tests. **The normative 33-case fixture corpus has not
yet been fully bound to evaluator outputs**, so CI does not claim full runtime
conformance; FOSS-459 owns that mapping.

Run `python3 scripts/security_contract.py --lint` and
`python3 -m unittest discover -s tests -p 'test_security_contract.py' -v`.

## Versioned Rust policy contracts (FOSS-429)

The cryptopolicy crate provides typed JSON DTOs for PolicyDocument, identifiers,
evaluation time, CryptoContext facts with source provenance, and PolicyDecision.
Parsing and SHA-256 fingerprinting do not execute a policy or authorize an
operation. The issuer is a claim, not proof of policy authenticity.

Try `cargo run -p cryptopolicy --example contract_smoke` and
`cargo test -p cryptopolicy --test contracts` once the dependency lockfile
has been generated. Inputs are strict JSON with a mandatory schema and
explicit default effect. Unknown fields, unexpected enum variants, duplicate
rule/fact IDs and oversized input are rejected. The 1 MiB limit is provisional;
FOSS-433 will supply centrally configured nested and structural limits.

Canonical encoding is versioned internally as cryptopolicy-canon-v1: ordered
typed fields; sorted rules, conjunctive requirements and metadata. It is NOT
RFC 8785 and must not be treated as interoperable signing serialization.

## Central resource limits (FOSS-433)

The Limits API bounds JSON bytes, nesting, rule counts, per-rule requirements,
metadata, context facts, decision reasons, matched rules, and evidence references.
Limits are validated before use, with hard ceilings even for caller overrides.
Parsing applies a quote-aware, allocation-free nesting preflight before
serde_json, which remains responsible for complete JSON syntax validation.

Use PolicyDocument::parse_json_with_limits, CryptoContext::parse_json_with_limits
or PolicyDecision::parse_json_with_limits. The default APIs use Limits::default.
Limits for imports, exceptions, external format adapters and diagnostic batching
are reserved contract fields and will be applied when those features exist;
they are NOT claimed to be operational enforcement today.

## Typed static policy validation (FOSS-434)

Finite typed selectors and mandatory requirements now support static validation,
contradiction detection, ordered redaction-safe diagnostics and explicit
missing-fact classifications. This is **not a policy evaluator or Permit**.

Try `cargo run -p cryptopolicy --example static_policy`, then
`cargo test -p cryptopolicy --test static_validation --locked`.
See [static validation contract](docs/STATIC_VALIDATION.md) for predicate
semantics, threat boundaries and unsupported runtime behavior.

## Deterministic offline evaluator (FOSS-435)

Use the pure `evaluate(policy, context, explicit_time)` API for typed,
bounded Permit/Deny/Indeterminate decisions with Deny precedence.
The evaluator requires explicit evidence and never treats missing required
data, unsupported algorithm identities or named profiles as Permit. It
does not independently authenticate the source or enforce access.

Run `cargo run -p cryptopolicy --example evaluate_offline`, then
`cargo test -p cryptopolicy --test evaluator --locked`. See
[the evaluator contract](docs/EVALUATOR.md) for the provisional algorithm
recognition table, single-fact restriction, time boundaries, test matrix
and remaining security controls.

## Baseline/overlay composition (FOSS-437)

Offline PolicySet compilation resolves exact pinned policy ID/version/digest
references and requires an independent Permit from every baseline, overlay
and imported policy layer. Cycles, unresolved imports and oversized graphs
abort atomically. The effective digest is a domain-separated SHA-256 of
the full versioned, order-independent dependency graph and policy content.

Run `cargo run -p cryptopolicy --example compose_offline` and
`cargo test -p cryptopolicy --test composition --locked`. See
[the canonical composition contract](docs/COMPOSITION.md) for precise
encoding, fail-closed semantics, resource limits and trust boundaries.

## Versioned algorithm/profile catalog (FOSS-445)

The standalone pqc-kit crate now exposes a source-traceable immutable v1
algorithm/profile catalog covering classical and NIST PQC parameter sets.
It enforces exact canonical names, parsing-only aliases, operation classes,
typed parameters and separate PQ categories vs key bit lengths. Catalog
membership is **not implementation approval or an authorization Permit**.

Run cargo run -p pqc-kit --example catalog_smoke and
cargo test -p pqc-kit --test catalog --locked. The reference contract is
[Algorithm Catalog](docs/ALGORITHM_CATALOG.md). FOSS-447/449 retain separate
evidence and provider-integration trust gates.

## Provenance-safe assessment (FOSS-447)

The offline AssessmentContext adapter preserves snapshot, source/evidence
identifiers, scoped activity, configured vs negotiated vs observed origin,
partial inspection coverage, and contradictory observations. Independently
authenticated operational records are evaluated one at a time through FOSS-435.
The assessment decision remains distinct from claimed confidence and coverage.
Untrusted, inferred, dependency-only, incomplete and conflicting evidence
does not grant Permit.

Try cargo run -p cryptopolicy --example assess_observations and
cargo test -p cryptopolicy --test assessment --locked. See
[the assessment contract](docs/ASSESSMENT.md) for exact v1 wire and trust
semantics. FOSS-315/335-339 own real Cryptomap projection; FOSS-459 owns
the full normative security-conformance corpus.

## Versioned Keymesh-style key capability preflight (FOSS-449)

The pure KeyRequest and ProviderCapabilitySnapshot APIs check exact FOSS-445
profile/operation/parameter identities, independently verified provider and
HSM assurance claims, time bounds, key origin, protection and exportability.
Unsupported or downgraded capabilities Deny; stale, unknown and unverified
metadata remain Indeterminate. Compatibility is NOT key-use evidence or a
cryptopolicy PolicyDecision.

Use cargo run -p cryptopolicy --example assess_key_capabilities and
cargo test -p cryptopolicy --test capability --locked. See
[the key capability contract](docs/KEY_CAPABILITY.md). No Keymesh crate is
required and no publishing is enabled.

## X.509 PQC identity normalization (FOSS-452)

The standalone pqc-x509 crate maps exact RFC 9881 ML-DSA certificate
signature identifiers and RFC 9935 ML-KEM SPKI DER to pinned FOSS-445
profiles. Strict bounded DER rejects unknown OIDs, parameters, BER encoding,
mismatched TBS/outer signatures, incorrect ML-KEM public-key lengths, and
uninspected or invalid critical/key-usage states. This is not a certificate
validator or PolicyDecision.

Run cargo run -p pqc-x509 --example normalize_x509 and
cargo test -p pqc-x509 --test identities --locked.
See [X.509 normalization](docs/X509_NORMALIZATION.md).

## RFC 9964 ML-DSA JOSE/JWK public identity (FOSS-455)

The `pqc-jose` crate normalizes only exact public AKP JWK ML-DSA-44/65/87 identities with separately extracted matching JWS protected-header JSON. Bounded strict JSON, canonical base64url, exact public-key sizes and a pinned catalog prevent algorithm confusion. No signature/key verification or PolicyDecision is performed; projection is always inferred and unverified. Run `cargo run -p pqc-jose --example normalize_jose` and `cargo test -p pqc-jose --test identities --locked`. See [the JOSE contract](docs/JOSE_NORMALIZATION.md).

## RFC 9964 COSE ML-DSA AKP identity normalization (FOSS-457)

The `pqc-cose` crate strictly parses a canonical CBOR COSE_Key and separately extracted protected-header map for exact ML-DSA-44/65/87 identifiers (-48/-49/-50), kty 7 (AKP) and label -1 public key. It rejects private label -2, unknown headers, all critical extensions, nonpreferred CBOR encoding and mismatched algorithms; it checks exact 1312/1952/2592-byte public-key lengths against a pinned pqc-kit catalog. It does not validate signatures, keys, identities, thumbprints or permissions. `CryptoContext` projection remains inferred and unverified.

Run `cargo run -p pqc-cose --example normalize_cose` and `cargo test -p pqc-cose --test identities --locked`. See [COSE normalization contract](docs/COSE_NORMALIZATION.md).

## RFC 10024 finalized hybrid TLS 1.3 group identities (FOSS-458)

The `pqc-kit::tls_hybrid` registry adds **only** three finalized hybrid TLS NamedGroups (X25519MLKEM768, SecP256r1MLKEM768 and SecP384r1MLKEM1024), each with exact RFC 10024 codepoints, classical+ML-KEM components, share ordering and lengths. This is separate from the immutable FOSS-445 catalog bytes; presence in either registry never authorizes a cryptographic operation. Configured groups cannot be mistaken for negotiated groups; draft Kyber codepoints remain explicitly obsoleted. The typed assessment can produce *structural metadata consistency* but never authenticated evidence or Permit.

Run `cargo run -p pqc-kit --example tls_hybrid` and `cargo test -p pqc-kit --test tls_hybrid --locked`. See [hybrid TLS identity contract](docs/TLS_HYBRID_PROFILES.md).

## Normative runtime conformance — incremental bridge (FOSS-459)

The original 33-case normative security contract remains **specification-only**. The [runtime conformance crosswalk](docs/CONFORMANCE_COVERAGE.md) explicitly accounts for all 33 cases, and binds 19 to real Rust evaluator/validation and provenance-safe assessment tests, leaving 14 pending with identified gaps. Assessment and provider evidence remain non-authorizing until authenticated externally. Both the crosswalk audit and runtime-bound cases are executed in CI. These checks assert actual outcomes and controlling reasons for the 8 cases; they do not claim a complete 33-case reason/error golden corpus. Run `python3 scripts/conformance_coverage.py` and `cargo test -p cryptopolicy --test normative_runtime --locked`.

FOSS-500/A now provides a **non-authorizing, simulated exact Deny waiver candidate** gated by two independent caller-owned verifiers and mandatory `Require` compensation. It preserves every other baseline/overlay layer and keeps the original policy digest. A candidate Permit is not an authenticated or enforceable authorization. See [waiver admission](docs/EXCEPTION_ADMISSION.md). `RuleRequirement` deviations and signed audit remain deferred to subsequent issues.

## Reviewed policy-owner waivability (FOSS-502)

The `cryptopolicy` crate now includes a strictly bounded, externally authenticated **waivability registry** and exact key/profile binding for offline waiver-candidate assessment. Separate caller-owned verifiers must authenticate the source approval, policy-owner grant, current registry/replay state, and actual key/profile ownership. An explicitly owner-waivable failed mandatory `Require` may be simulated with independently satisfied compensating controls, without changing any other policy layer. Neither a registry match nor a hypothetical candidate Permit constitutes enforcement authorization. See [waivability security contract](docs/WAIVABILITY.md). The original 33-case normative conformance corpus remains unchanged.

## Exact-scope exception reference (FOSS-499)

The `cryptopolicy` crate now includes a bounded, strictly versioned, **untrusted** exception-reference DTO and external-verification interface. The default verifier rejects source/approval trust, and even a caller-verified reference is only *eligible for future independent admission*; it does not waive rules, override Deny, execute cryptography or grant Permit. The reference pins exact policy ID/version/digest, target rule, tenant, environment, operation, algorithm and key, with explicit time and compensating rule references. Run `cargo run -p cryptopolicy --example exception_reference`; see [exception trust contract](docs/EXCEPTION_REFERENCE.md). FOSS-500/501 implement future admission/audit separately.

## Crates

- cryptopolicy
- pqc-kit
- pqc-x509
- pqc-jose
- pqc-cose

## Development

Run:

    cargo fmt --all -- --check
    cargo check --workspace --all-targets --all-features
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    cargo test --workspace --all-features

## External-consumer preview acceptance (FOSS-440)

A separate Rust application under `acceptance/fresh-consumer` consumes an exact pinned Git revision without local workspace path dependencies, parses policy/context JSON, and checks Permit/Deny/Indeterminate decisions and stable decision decoding. This is **not** final packaged-crate acceptance; see [consumer acceptance](acceptance/fresh-consumer/README.md) and FOSS-464 release gates.

## Packaged-crate candidate acceptance (FOSS-440)

Run `python3 -m unittest discover -s tests -p test_package_acceptance.py -v` and `python3 scripts/package_acceptance.py` to test `.crate` archives via a temporary loopback-only Cargo sparse registry and version-only external consumer. Source manifests remain `publish = false`; only disposable staging copies can be packaged. Real registry ownership, SBOM attestations and independent publication approvals remain FOSS-464/466 blockers. See [acceptance contract](docs/PACKAGE_ACCEPTANCE.md).

## Publishing

All five workspace packages are **unpublished bootstrap crates** with `publish = false`.
The default `main` workflow can propose a release PR but **cannot publish**.
Only `.github/workflows/release-publish.yml` contains the publication command.

Publication is disabled unless a maintainer deliberately completes the protected
release setup: a `workflow_dispatch` on `main`, exact `PUBLISH` confirmation,
repository variable `CRYPTOPOLICY_RELEASES_ENABLED=true`, and the
`crates-io-publish` GitHub environment. That environment **must** be
configured with required reviewers and main-branch deployment restrictions
before enabling the repository variable. There is no release scheduled by this PR.

CI checks all crate manifests and workflow triggers with
`scripts/release_guard.py` and adversarial regression tests. Before any
published package, a separately reviewed change must authorize that crate,
validate crates.io ownership and the public API, and update the bootstrap guard.

See [release controls and operator procedure](docs/RELEASING.md).

## License

Licensed under either:

- Apache License, Version 2.0
- MIT License

at your option.