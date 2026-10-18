# FOSS-452 — Bounded X.509 PQC identity normalization v1

pqc-x509 exposes two bounded semantic DER entrypoints: normalize_ml_dsa_certificate_signature(inner_der, outer_der, critical_extensions, evidence) and normalize_ml_kem_spki(spki_der, critical_extensions, key_usage, evidence). Each also offers an _with_limits form.

These functions do NOT parse complete X.509 certificates, authenticate the source parser, verify signatures, validate trust chains or revocation, perform cryptographic key checks, or authorize policy operations. A security-reviewed independent RFC 5280 parser must extract the exact TBS/outer AlgorithmIdentifier fields or standalone SPKI and actually check the certificate-wide keyUsage and unknown critical extensions. The caller-supplied CriticalExtensions and MlKemKeyUsage states are ASSERTIONS, not attestations.

## Exact published profiles

RFC 9881 (October 2025): ML-DSA certificate signature AlgorithmIdentifiers, with PARAMETERS ABSENT (including no ASN.1 NULL).

| Profile | OID | DER AlgorithmIdentifier |
|---|---|---|
| ML-DSA-44 | 2.16.840.1.101.3.4.3.17 | 300b0609608648016503040311 |
| ML-DSA-65 | 2.16.840.1.101.3.4.3.18 | 300b0609608648016503040312 |
| ML-DSA-87 | 2.16.840.1.101.3.4.3.19 | 300b0609608648016503040313 |

Source: https://www.rfc-editor.org/rfc/rfc9881.html

RFC 9935 (March 2026): ML-KEM SPKI AlgorithmIdentifiers, with PARAMETERS ABSENT. The subjectPublicKey BIT STRING contains the RAW public key bytes, unused bits zero, without OCTET STRING nesting. If keyUsage exists, ONLY keyEncipherment may be set.

| Profile | OID | DER AlgorithmIdentifier | Public key octets |
|---|---|---|---|
| ML-KEM-512 | 2.16.840.1.101.3.4.4.1 | 300b0609608648016503040401 | 800 |
| ML-KEM-768 | 2.16.840.1.101.3.4.4.2 | 300b0609608648016503040402 | 1184 |
| ML-KEM-1024 | 2.16.840.1.101.3.4.4.3 | 300b0609608648016503040403 | 1568 |

Source: https://www.rfc-editor.org/rfc/rfc9935.html

Exactly these six role-bound OID encodings are accepted. No unknown/draft OIDs, Kyber/Dilithium aliases, fallback to related security categories, explicit NULL parameters or profile downgrades. An immutable pqc-kit v1 catalog supplies exact canonical profile and operation matching (Verify for ML-DSA signatures, Encapsulate for ML-KEM SPKI). Catalog status is specification metadata, not provider validation or a policy Permit.

## Bounded DER security

Only two shallow DER grammars are parsed:
- AlgorithmIdentifier SEQUENCE containing exactly one OBJECT IDENTIFIER.
- SubjectPublicKeyInfo SEQUENCE containing exactly an AlgorithmIdentifier and a BIT STRING with zero unused bits and the exact 800, 1184 or 1568 raw key octets.

Canonical DER length encoding, tags, well-formed base128 OIDs, full input consumption, no trailing fields, exact inner/outer signature identifiers, and explicit critical/keyUsage state are required. BER indefinite length, nonminimal DER, truncated buffers, appended NULL, extra/duplicate fields, unknown critical extensions and unchecked extension state are rejected with stable redaction-safe typed errors.

Maximum AlgorithmIdentifier DER: 96 bytes; maximum SPKI DER: 4096 bytes; maximum serialized report: 8192 bytes; source and evidence handles: ASCII-safe, nonempty, at most 128 bytes. Lower caller budgets are supported; raising absolute maxima is rejected.

## Output provenance, not proof

The strict v1 X509AlgorithmIdentity report includes source_id/evidence_ref, exact dotted OID, field role, canonical profile, absent-parameter state, optional public-key size, source RFC, pinned pqc-kit catalog version/digest, and SHA-256 of original input DER. It does not serialize raw public keys. Both signature_verified and certificate_validated are always false, including after strict JSON parsing. The original DER fingerprint uses explicit domain separation:
- Signature pair: ASCII "pqc-x509-ml-dsa-signature-pair-v1" + zero + u32 big-endian inner DER size + inner DER + outer DER.
- SPKI: ASCII "pqc-x509-ml-kem-spki-v1" + zero + entire SPKI DER.

These are deterministic correlation checksums, not verified issuer signatures or authenticated evidence.

## Reproduction

    cargo run -p pqc-x509 --example normalize_x509
    cargo test -p pqc-x509 --test identities --locked
    cargo fmt --all -- --check
    cargo check --workspace --all-targets --all-features --locked
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo test --workspace --all-features --locked
    RUSTDOCFLAGS=-Dwarnings cargo doc --workspace --all-features --no-deps --locked

Fixture catalogs pin all six OIDs and DER encodings. Structured golden outputs pin the ML-DSA-44 signature pair and ML-KEM-768 SPKI evidence identity/digests. Negative tests include malformed DER, BER encodings, unknown roles, explicit parameters, uninspected critical extensions, incompatible keyUsage, size limits, strict output parsing and byte mutations. The synthetic public-key payloads in tests/example are intentionally NOT cryptographic keys and demonstrate structural identity only.

## Next gates

FOSS-455 (JOSE), FOSS-457 (COSE) and FOSS-458 (hybrid TLS) remain separate format increments. FOSS-459 owns full independently reviewed 33-case normative runtime conformance and must integrate these vectors. FOSS-315 remains the Cryptomap source-mapping boundary. FOSS-466 remains GitHub administrator release approval. All five bootstrap crates remain publish=false.
