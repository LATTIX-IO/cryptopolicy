# FOSS-445 — Versioned NIST algorithm/profile catalog v1

## Scope and trust

This is a frozen algorithm **specification inventory**, not an authorization database. It lives in pqc-kit without depending on cryptopolicy, X.509, JOSE, COSE, or proprietary Lattix services.

Snapshot data: crates/pqc-kit/data/catalog-v1.json, schema_version "1", catalog_version "1.0.0", as_of "2026-10-17", 36 sorted profiles. SHA-256 of the exact bytes is pinned by EMBEDDED_CATALOG_SHA256_V1; this protects against accidental source drift, but is **not a signature or independent supply-chain attestation**. Updating the fixture requires an explicitly reviewed source/version change. The parser intentionally does not download updates.

Each entry has canonical ID, algorithm family, maturity status, exact operation classes, mandatory typed parameter, security metadata, citation and revision, and parser-only aliases. Unknown keys and variants, duplicate keys, oversized input, duplicate/unsorted IDs, unreviewed aliases, incompatible operation lists, incorrect category metadata or malformed sources fail validation.

Supported public APIs: Catalog::embedded_v1(), Catalog::parse_untrusted_json(bytes), Catalog::get(canonical_id), Catalog::resolve_name(external_id), Catalog::validate_usage(canonical_id, operation, parameter).

## Typed parameters and lifecycle

- UsageParameter::KeyBits(n) specifies key bits for AES/RSA/ECDSA and legacy TDEA.
- UsageParameter::HashOutputBits(n) specifies fixed SHA-2/3 digest length, not key size.
- UsageParameter::NamedSet(exact_id) specifies a full ML-KEM, ML-DSA, SLH-DSA or draft candidate profile.
- classical_bits and pqc_category are independent optional attributes; **do not** map PQ parameter-name numbers to key bits. ML-KEM categories 1/3/5 apply to 512/768/1024, ML-DSA categories 2/3/5 apply to 44/65/87, SLH-DSA categories 1/3/5 apply to SHA2/SHAKE 128/192/256 s/f.
- Status standardized/experimental/deprecated/unsupported describes specification maturity within this frozen catalog. It **does not** mean approved or prohibited by a specific tenant, provider or CMVP configuration. For this catalog's conservative usage check, all non-standardized records are rejected.

Aliases are exact-case parser-only strings; AES256-GCM and SHA3_256 are explicitly recognized but cannot be passed to validate_usage. Kyber-1024, Dilithium5, SPHINCS+, ambiguous and invented identifiers are rejected rather than automatically mapped to FIPS identities.

## Primary standards references (retrieved 2026-10-17)

| Family | Profiles | Normative source |
|---|---|---|
| AES-GCM | AES-128/192/256-GCM | [FIPS 197](https://csrc.nist.gov/pubs/fips/197/final), NIST SP 800-38D |
| SHA-2 | SHA-256/384/512 | [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) |
| SHA-3 | SHA3-256/384/512 | [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final) |
| RSA/ECC | RSA-PSS-2048/3072/4096, ECDSA-P256/P384/P521 | [FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final), SP 800-186 |
| ML-KEM | ML-KEM-512/768/1024 | [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) |
| ML-DSA | ML-DSA-44/65/87 | [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) |
| SLH-DSA | Twelve SHA2/SHAKE × 128/192/256 × s/f sets | [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) |
| Experimental | FALCON-512 candidate, not an approved FN-DSA profile | [NIST digital signatures program](https://csrc.nist.gov/Projects/digital-signatures) |
| Deprecated | TDEA-3KEY for legacy decryption only | [SP 800-67 withdrawal](https://csrc.nist.gov/News/2023/nist-to-withdraw-sp-800-67-rev-2) |
| Unsupported | RSA-PSS-1024 | [SP 800-131A Rev 2](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final) |

33 standardized, 1 experimental, 1 deprecated and 1 unsupported. Standardization of FIPS 203/204/205 does not imply correct parameter handling or a FIPS-validated cryptographic implementation; sources may carry later errata. NIST parameter security categories are not equivalent to key bit lengths. Existing cryptopolicy::evaluate remains conservative and is not wired to convert any catalog entry into Permit.

## Verification and later increments

    cargo run -p pqc-kit --example catalog_smoke
    cargo test -p pqc-kit --test catalog --locked
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo test --workspace --all-features --locked

FOSS-447 owns provenance-safe multi-fact assessment. FOSS-449 owns provider/key capability trust. FOSS-452/455/457 own X.509/JOSE/COSE adapters; FOSS-458 owns named hybrids; FOSS-459 owns full normative decision conformance. FOSS-466 still blocks crates.io publication.
