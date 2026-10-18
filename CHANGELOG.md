# Changelog

All notable changes to this project will be documented in this file.

The project follows Semantic Versioning once its public API reaches a stable contract. Pre-1.0 releases may evolve more rapidly, with breaking changes documented here.

## [Unreleased]

### Added

- FOSS-457: bounded deterministic RFC 9964 COSE_Key + protected header parsing for ML-DSA-44/65/87. Exact -48/-49/-50 algorithm IDs, kty 7, public-key sizes, pinned catalog mapping, canonical CBOR length/order checks, duplicate/critical/unknown/private-label rejection, unverified context projection, independent golden vectors and adversarial mutation tests. No signature/key verification, CWT identity validation or publication.

- FOSS-455: bounded RFC 9964 ML-DSA-44/65/87 AKP public JWK and protected JWS header normalization; strict alg/kty/key-length/canonical-base64url and critical-extension rejection, catalog identity, provenance fingerprint, unverified CryptoContext projection, adversarial vectors and executable example. No signature/key verification, private-key handling or authorization.

- FOSS-452: bounded RFC 9881 ML-DSA X.509 signature and RFC 9935 ML-KEM SPKI DER normalization with exact no-parameter OIDs, pinned pqc-kit profile identity, strict DER/tag/key-usage/critical-extension checks, provenance-only versioned reports, positive/malformed fixtures, mutation regressions and offline example. Not a certificate verifier or policy authority.

- FOSS-449: strict versioned key-request/provider-capability preflight DTOs, pinned pqc-kit profile recognition, explicit required/forbidden key capabilities, separate source and HSM assurance verifier, age/expiry handling, fail-closed deterministic results, standalone fixtures and adversarial Rust tests. Compatibility is not policy authorization.

- FOSS-447: strict AssessmentContext v1, provenance-preserving per-observation sources and typed parameters, external evidence-verifier boundary, partial coverage/conflict reporting, deterministic single-fact core decision aggregation and adversarial golden tests; no cryptomap dependency or implicit authorization upgrade.

- FOSS-445: immutable SHA-256-pinned v1 pqc-kit catalog of classical and FIPS 203/204/205 PQC profiles, with exact aliases, typed parameters, lifecycle status, standards provenance and adversarial regressions; no evaluator authorization change.

- FOSS-437: atomic offline PolicySet/EffectivePolicy resolver, pinned baseline and overlay imports, strict conjunctive decisions, domain-separated binary canonical digest and graph adversarial tests.

- FOSS-435: pure deterministic single-context policy evaluator with deny-first tri-state decisions, bounded outputs, explicit-time handling, provisional strict algorithm recognition and adversarial/golden tests; source authenticity and registry approval remain external.

- FOSS-434: finite typed selector and requirement contracts, deterministic static validation/diagnostics, missing-fact dispositions, negative parser and conflict tests; no runtime evaluator.

- FOSS-429: strict Rust/JSON schema types, explicit fallback, context fact provenance, validated identifiers, canonical SHA-256 and negative parsing tests.

### Changed

### Fixed

### Security

- FOSS-433: bounded policy/context/decision deserialization and caller-validated structural resource budgets, including adversarial over-limit tests.

- FOSS-426: Add versioned threat model, fail-closed safety invariants, adversarial golden security fixtures, a specification linter, and an opt-in future evaluator results comparator.

- FOSS-424: Explicitly disable publication for all bootstrap crates; separate release proposals from a guarded manual publishing workflow; add manifest/workflow regression checks.
