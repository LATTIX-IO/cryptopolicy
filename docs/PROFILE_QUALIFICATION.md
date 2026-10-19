# FOSS-503/A / FOSS-505 — Exact source-attested profile qualification

This is an **offline metadata qualifier**, not a crypto library, a signed
attestation, a policy Permit, a waiver, a FIPS certification or a provider
authorization. The public `evaluate_with_limits` API and FOSS-502 owner
waiver admission intentionally remain **fail closed** on facts containing
a `profile_id`. This increment does not alter those invariants.

## Identity and source boundaries

`qualify_embedded_profile(request, source_verifier, key_verifier)` accepts
a single explicit `CryptoContext`, an exact `ExceptionScope` (tenant,
environment, operation, algorithm, key), FOSS-502 `KeyProfileBinding`,
`ProfileParameterWitness` (exact key bits or canonical named PQ parameter
set), caller bounds and an explicit UTC evaluation timestamp.

The embedded, immutable `pqc-kit::Catalog::embedded_v1()` is read and its
exact fingerprint is compared with
`pqc_kit::EMBEDDED_CATALOG_SHA256_V1`. Only exact canonical
`Catalog::validate_usage()` identity, operation, standardized lifecycle
status, and mandatory parameters are accepted. No alias normalization or
fuzzy family matching is accepted on an authorization-adjacent path.
In this first increment, `ProfileId` must match the exact canonical
algorithm ID. Multi-identifier hybrid constructions are out of scope.

A catalog match says nothing about the provenance of the actual key.
The following are **separate**, caller-owned verification gates:

- `KeyProfileBindingVerifier` authenticates actual tenant/key generation,
  key owner, named profile, and source binding; the default rejects all.
- `ProfileEvidenceVerifier` authenticates source observation, exact provider,
  attested parameter set, and current signer/key revocation; the default
  returns all false.

A fact's `verified=true` and `source_quality=externally_verified` fields
are only claims. They are necessary consistency hints but not proof.
The source must actually be `Observed` or `Negotiated`, carry an exact
matching evidence reference and have explicit provider metadata. Configured,
requested, inferred and provider-capability-only facts remain ineligible.

The return type `ProfileQualificationReport` includes only pinned catalog
content digest, canonical algorithm/profile, operation, explicit time,
and one `ProfileQualificationFinding`. It includes **no** raw key bytes,
provider credentials, approval/issuer strings, source payloads, private keys,
or access token. `ReadyForVerifiedEvaluator` means only that the external
verifiers claim sufficient identity evidence for the **future**
catalog-aware policy evaluation in FOSS-503/B; it is never an authorization
to execute cryptography.

## Supported and intentionally unsupported parameter forms

- Key-bit witness: an exact integer, matching both the claimed observed key
  bits and the canonical `pqc-kit` KeyBits parameter (e.g. AES-256-GCM).
- Named-set witness: exact canonical named parameter identity with no
  contradictory key-size claim (e.g. ML-DSA-65 or ML-KEM-1024).
- Hash digest output-size qualification and multi-component/hybrid profiles
  remain deferred until the fact schema can represent their parameters
  without interpreting an algorithm label as independent evidence.

Source verification failures return conservative findings, never Permit.
Unknown, parsing-only aliases, experimental, deprecated, unsupported,
operation-incompatible and parameter-mismatched profiles are rejected.

## Reproduction

    cargo run -p cryptopolicy --example profile_qualification
    cargo test -p cryptopolicy --test profile_qualification --locked
    cargo test --workspace --all-features --locked
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

Tests exercise pinned AES and ML-DSA/ML-KEM canonical identities, source/
provider/key trust separation, versioned key generation and revocation
negative cases, missing or configured-only evidence, alias and experimental
profiles, profile/tenant/key/operation/environment/time substitution,
resource limits, replay stability, and the unchanged Indeterminate from the
ordinary v1 evaluator. Positive verifiers are synthetic fixed test stubs,
**not** deployment trust roots.

This does not change the FOSS-459 33-case conformance crosswalk, crate
publishing controls, or any of the five `publish=false` manifests.
FOSS-503/B owns integrating qualified evidence with the real deterministic
policy evaluator and the still-unimplemented positive waiver/compensating
Require scenario; FOSS-501 owns separate auditable enforcement decisions.
