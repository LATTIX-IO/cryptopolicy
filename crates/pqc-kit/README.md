# pqc-kit

Adapter-independent immutable versioned NIST algorithm/profile catalog (FOSS-445).

The crate identifies exact canonical profiles, narrowly allowlisted parser-only aliases, operations, required parameters, classical strength vs NIST PQ security category, and source revisions. It **does not** perform cryptography, approve modules/providers, authenticate identities or produce policy decisions.

## Reproduce

    cargo run -p pqc-kit --example catalog_smoke
    cargo test -p pqc-kit --test catalog --locked
    cargo test --workspace --all-features --locked

The embedded data is in data/catalog-v1.json. Its exact bytes are pinned by EMBEDDED_CATALOG_SHA256_V1. Updates require independently reviewed fixture and checksum changes.

## Safety

- Standardized describes a *specification*, not FIPS 140-3/CMVP implementation validation or tenant approval.
- ML-KEM-768 is a category-3 *parameter-set identifier*, not a 768-bit key. ML-DSA/SLH-DSA suffixes are not key sizes either.
- Catalog::resolve_name is exact-case alias parsing; validate_usage requires a canonical ID and correctly typed parameters.
- No implicit upgrade of cryptopolicy::evaluate or its single-fact, authenticity, registry and profile trust gates.
- parse_untrusted_json validates shape but cannot verify that an external publisher is NIST.
- All five crates remain publish=false. FOSS-466 administrator approval remains required.

See ../../docs/ALGORITHM_CATALOG.md for sources, binary data contract, status semantics, and security scope.

## RFC 10024 hybrid TLS constructions (FOSS-458)

The `pqc_kit::tls_hybrid` module registers exact published TLS hybrid groups
4587/4588/4589, distinguishes configured from negotiated evidence, rejects
obsoleted draft and unknown codepoints, and checks RFC 10024 share lengths.
It never verifies a TLS transcript or authorizes an operation.

    cargo run -p pqc-kit --example tls_hybrid
    cargo test -p pqc-kit --test tls_hybrid --locked

See [TLS hybrid contract](../../docs/TLS_HYBRID_PROFILES.md).
