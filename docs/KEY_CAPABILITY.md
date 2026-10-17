# FOSS-449 — Key and provider capability preflight, contract v1

## Role and security boundary

FOSS-449 implements offline compatibility assessment for versioned KeyRequest and ProviderCapabilitySnapshot records. It consumes Keymesh-style external JSON without a Keymesh crate dependency, network calls, provider interaction, filesystem/clock reads or private key material.

The returned CapabilityReport is **not** PolicyDecision. A compatibility Permit says only that exact, independently authenticated provider capability claims satisfy the requested **preflight** constraints. It never authorizes key creation/use, proves that any cryptographic operation occurred, attests an implementation against CMVP/FIPS 140-3, or authenticates a policy issuer. A separate, authenticated cryptopolicy Permit and enforcing PEP are mandatory for protected actions. The caller must implement a secure ProviderClaimVerifier; the library does no signature or hardware attestation verification. Equality checks in the runnable example are test fixtures, **not** production verification.

The crate has a one-way local dependency on the independent pqc-kit library. The exact embedded reviewed FOSS-445 catalog is version 1.0.0 and SHA-256 91cca1ed7fe8a0391045801108089bb38bee0b34fdff40e2c7e0fac4e87fb685. SHA-256 is not a publisher signature. Catalog membership describes algorithm specification status only and is not provider approval.

## Owned versioned DTOs

KeyRequest contains schema_version, request_id, provider_id, optional opaque key_ref, canonical algorithm_id, CryptoOperation, exact KeyParameter, evaluation_time, maximum accepted evidence age, catalog_version and catalog_digest, and arrays of typed RequiredCapability and ForbiddenCapability. KeyParameter is key_bits(u32) or named_set(exact AlgorithmId), never an inferred PQ category. No unreviewed alias or family-wide fallback is permitted.

ProviderCapabilitySnapshot contains the exact provider/snapshot ID, schema and catalog binding, and independently preserved ProviderCapabilityClaim records. Each claim contains original claim_id, source_id, optional exact key_ref, evidence_ref, algorithm, operation, exact parameter, support availability (supported/unsupported/unknown), optional key origin, exportability, protection, assurance claim/ref, asserted_at and exclusive expires_at.

ProviderClaimVerifier::verify(request, snapshot, claim) returns separately source_authenticated and assurance_authenticated. The production verifier MUST bind the exact request, provider, key_ref (if supplied), snapshot, original source, claim, signed evidence, independent assurance issuer/ref, revocation state and validity. A string labelled HSM, provider-verified, independently assessed or a catalog entry cannot authenticate its own source. UnverifiedProviderClaims always returns both flags false.

Required capabilities: exact known key_origin (provider_generated, imported, derived), non_exportable, minimum protection class, and independent_assurance. Hardware-backed and HSM minimum protection cannot be established without independently verified assurance. Forbidden capabilities: exportable, exact key origin, or exact protection class (typically software). All requirements compose by AND. An unknown origin, omitted exportability/protection or missing independent assurance remains Indeterminate, never implicitly safe.

The algorithm operation and exact named/bit parameter are validated against the FOSS-445 pinned catalog. Hash, key agreement and derivation requests are outside the key-operation contract. Unknown, alias-only, experimental, deprecated, unsupported or incompatible algorithm/operation/parameters Deny. AES-256-GCM cannot be substituted with AES-128-GCM; ML-KEM-1024 cannot be substituted with ML-KEM-768 or a fictional 1024-bit key. Only same-family security category/strength comparisons are permitted; categories are not bit counts.

## Deterministic fail-closed evaluation

1. Validate both strict schema-v1 JSON DTOs, input/output resource budgets, unique claim and constraint IDs, exact provider/catalog matching, nonzero age bound <= 30 days, and claim asserted_at earlier than exclusive expires_at. Error outputs do not authorize anything.
2. Load the embedded pinned pqc-kit catalog. Reject unsupported requested profiles and inconsistent operation/typed parameters before interpreting provider support. No dynamic registry imports or approximate alias recognition.
3. Sort claim IDs, preserving original source/evidence names and reasons. Only exact requested profile/operation or explicit weaker same-family profile claims participate; unrelated capabilities remain findings and never fulfill another claim.
4. For applicable claims, first require exact matching optional key_ref (a generic provider-wide claim must never authorize a different or particular existing key), then require original evidence_ref and independently verify the entire exact binding through ProviderClaimVerifier. Claims issued in the future, expired at the injected time or exceeding maximum age remain Indeterminate. Neither provider self-assertion nor mere claim authentication can prove independent hardware assurance.
5. An authenticated explicit unsupported claim, weaker same-family profile, invalid exact parameter or definite forbidden/violated property Deny. Unknown, stale, unverified or missing required attributes remain Indeterminate. Multiple conflicting applicable claims prevent Permit (definitive Deny retains precedence).
6. Only a fresh independently authenticated exact supported profile with every required/forbidden property known and satisfied, no conflicting claims, and required independent assurance proven can produce a compatibility-only Permit.
7. Output CapabilityReport with typed Deny/Indeterminate/Permit, stable reason codes, original-ID ordered findings, source and assurance verification flags, catalog pin and provider/request identities. Do not output key bytes, credentials or secrets. Report parsing alone does not prove the report producer is trusted.

Input and output JSON are strict closed records. Duplicate/invalid identifiers, mismatched catalog pins, malformed status/critical fields, stale/future evidence and excessive claim counts are not repaired, inferred or truncated. Claim counts are capped at 128 (or smaller FOSS-433 Limits.max_facts); combined requirements+forbiddens are bounded by max_requirements_per_rule; max_adapter_bytes, max_json_bytes, nesting and diagnostic limits remain enforced.

## Reproduction

    cargo run -p cryptopolicy --example assess_key_capabilities
    cargo test -p cryptopolicy --test capability --locked
    cargo fmt --all -- --check
    cargo check --workspace --all-targets --all-features --locked
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo test --workspace --all-features --locked
    RUSTDOCFLAGS=-Dwarnings cargo doc --workspace --all-features --no-deps --locked

Tests cover authenticated positive profile, default-untrusted source, distinct independently verified assurance, unknown provider, authenticated explicit unsupported and forbidden properties, HSM safeguards, stale/expired/future timestamps and inclusive exact age boundary, unknown/alias/experimental profile, AES and ML-KEM downgrade, duplicate/malformed JSON, provider/catalog spoofing, source identifier tampering, error propagation, resource limits and insertion order permutations. Golden JSON fixes explicit source/catalog identities, outcomes and reason ordering; CI must never auto-overwrite expected goldens.

## Deferred ownership

FOSS-447 is the separately delivered *observed activity* assessment. FOSS-315/335–339 own actual Cryptomap projection. FOSS-451/452/455/457/458 cover transition exports and standardized protocol/format profiles. FOSS-459 owns the independent complete normative 33-case conformance corpus. FOSS-466 is the administrator-only environment reviewer/credential gate. No registry publication or manifest release enablement occurs in FOSS-449.
