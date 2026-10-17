# FOSS-447 - Provenance-safe third-party cryptographic assessment v1

## Scope and non-goals

Cryptopolicy owns a neutral AssessmentContext v1 model and a deterministic offline assessment adapter. It accepts external JSON from inventory and telemetry adapters without requiring the Cryptomap Rust crate. External mapping from Cryptomap InventorySnapshot, asset/use-site relationships, source coverage, and original evidence is a separate FOSS-315 / FOSS-335-339 deliverable. FOSS-447 does not add scanners, authenticate collector implementations, infer observed activity from dependencies, enable policy enforcement, or change FOSS-435 evaluator semantics.

Public Rust APIs:

- AssessmentContext::parse_json_with_limits(input, &Limits) and AssessmentContext::validate(&Limits)
- assess(policy, assessment, explicit_time, &impl EvidenceVerifier)
- assess_with_limits(policy, assessment, explicit_time, verifier, &Limits)
- AssessmentReport::parse_json_with_limits(...)
- UnverifiedEvidence as a default verifier that never authenticates imported claims.

The library itself performs no network I/O, TLS, signatures, filesystem lookup, wall-clock reads, or cryptographic provider invocations. The EvidenceVerifier is a caller-injected trust boundary: callers must verify the exact snapshot, original observation, collector/source, evidence, asset/use-site/session, and validity of the underlying artifact. Merely passing a verifier that returns true is not cryptographic proof.

## Assessment input fields

AssessmentContext requires schema_version, assessment_id, snapshot_id, one explicit scope, operation, evaluation_time, environment, coverage, uninspected_sources, and observations. The scope has asset_id, use_site_id, and activity_id; observations must bind to exactly these IDs. For TLS, activity_id denotes one session/handshake. Distinct handshakes must be assessed separately before a higher-level rollup, to avoid declaring legitimate different negotiations contradictory or combining attributes across unrelated sessions.

Each observation retains original observation_id, source_id, evidence_ref (nullable), exact scope, kind, optional operation/algorithm/profile, parameter, CryptoProperties, observed_at and confidence. No property is taken from another record. Classification is:

| Kind | FactOrigin | Policy-evaluation eligibility |
|---|---|---|
| direct_operation | observed | Matching operation, externally authenticated evidence |
| negotiated_protocol | negotiated | Matching operation, externally authenticated evidence |
| configuration | configured | No; configuration is not observed use |
| installed_dependency | inferred | No; dependency is not observed use |
| provider_capability | provider_capability | No; support is not observed use |
| inferred | inferred | No; hypothesis is not observed use |

An operational observation requires an exact algorithm_id and typed parameter to be eligible. Parameter kinds key_bits, hash_output_bits, named_set use exact unsigned bit lengths or exact AlgorithmId. Numeric PQ algorithm suffixes are not automatically converted to key lengths. Contradictory key bits, mismatched named sets, invalid numbers and incompatible SHA/SHA3 output lengths are rejected before evaluation. The FOSS-445 pqc-kit inventory is independent and does not confer automatic Permit.

Coverage has values uninspected, partial and complete. A complete coverage claim with explicit uninspected sources is internally contradictory and rejected. A complete claim with zero actual observations is still Indeterminate: empty inventory does not prove absence of cryptographic usage. Confidence low/medium/high is separately reported and is not proof of authenticity.

## Source-verification and projection algorithm

1. Parse and validate the entire context under FOSS-433 budgets. Reject scope mismatches, duplicate original IDs, future source timestamps, invalid typed parameters, inconsistent coverage and excess records.
2. Sort original observations by observation_id and preserve source/evidence references verbatim in findings. Non-operational and different-operation entries remain findings only.
3. Do not fill missing algorithm/parameter attributes from sibling records, aliases, providers, configurations, inferred dependencies or separate sessions. A missing evidence reference cannot authenticate.
4. EvidenceVerifier must validate the exact snapshot, asset/use-site/session, source, observation, evidence binding. Only an accepted direct/negotiated record is projected to FOSS-435. The adapter derives verified=true and source_quality=externally_verified solely from that independent verification result; original source_quality and confidence remain untrusted assertions. Unverified observations are findings only and cannot reach the core policy evaluator as proven use.
5. Each accepted observation becomes its own single-fact CryptoContext. FOSS-435's one-target limit remains intact. No multi-fact joins, coalescing or partial attribute inheritance.
6. One definitive independently supported core Deny, or a global explicit/temporal Deny, dominates all. A candidate Permit requires complete coverage, zero operational conflicts, at least one matching observation, every required observation authenticated and claiming High confidence, and every per-observation PolicyDecision Permit. Otherwise absent/unknown coverage, missing observations, weaker confidence, conflict, missing provenance or core Indeterminate yields Indeterminate.
7. AssessmentReport includes the exact assessed operation, original sorted uninspected source IDs, aggregate outcome, separate coverage and minimum claimed evidence_confidence, stable assessment reason codes, original-ID conflict pairs, and original-ID per-source findings. Every finding also preserves original operation, algorithm/profile names, typed parameter and observation time with its optional one-fact core decision. This is data, not an authenticated enforcement token.

Configured TLS and a negotiated TLS handshake remain separate kinds. A negotiated handshake is only eligible if the requested policy supports negotiated origin; it is not silently promoted to direct operation. Installed OpenSSL/dependency presence never becomes actual algorithm usage.

## Conflict and resource semantics

For the same scope/activity and operation, direct/negotiated observations are compared pairwise for exact populated mismatches in algorithm, profile, typed parameter, security category, provider, key protection, key exportability, key bit lengths and data sensitivity. Two distinct populated values create ObservationConflict(first, second, field). Missing values remain missing; no winner is selected by arrival order or claimed confidence. Even two independently individually permitting observations produce Indeterminate when they contradict; a separate definitive Deny wins.

To prevent quadratic denial of service, at most 128 observations (or a lower Limits.max_facts) are accepted. Limits.max_diagnostics bounds conflict pairs; other FOSS-433 limits bound source lists, reasons, JSON bytes, nesting and output. On overflow, compilation returns a typed error rather than truncating evidence or manufacturing a Permit.

## Reproduction and follow-on

    cargo run -p cryptopolicy --example assess_observations
    cargo test -p cryptopolicy --test assessment --locked
    cargo fmt --all -- --check
    cargo check --workspace --all-targets --all-features --locked
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo test --workspace --all-features --locked
    RUSTDOCFLAGS=-Dwarnings cargo doc --workspace --all-features --no-deps --locked

Checked-in fixtures cover observed TLS operation, negotiated TLS, configured cipher, benign dependency, uninspected source, partial inspection and contradictory observations. A golden result fixture pins original reference preservation, stable reason codes and FOSS-435 canonical digest. Tests cover order permutations, input tampering, original provenance binding, missing facts, observer clock mismatch, conflict limits and verifier failures.

FOSS-315/335-339 owns actual Cryptomap inventory projection. FOSS-449 owns Keymesh/provider capability trust. FOSS-458 owns named hybrid profiles. FOSS-459 owns the full normative 33-case security conformance suite. FOSS-466 remains the independent GitHub release-approval gate, and all five workspace crates retain publish=false. Actual enforcement requires authenticated policy issuer and a trustworthy externally implemented verifier and PEP; this library supplies none of them.
