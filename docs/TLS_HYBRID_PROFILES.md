# FOSS-458 — RFC 10024 TLS 1.3 hybrid transition profiles

Three **finalized** IANA TLS NamedGroup codepoints are registered as
immutable typed construction identities, separately from the FOSS-445
immutable algorithm catalog. Pinned catalog bytes and SHA-256 remain unchanged.

| NamedGroup | Decimal (hex) | Classical + PQ | Client share | Server share | Concatenated secret | Wire order |
|---|---|---|---:|---:|---:|---|
| X25519MLKEM768 | 4588 (0x11EC) | X25519 + ML-KEM-768 | 1216 | 1120 | 64 | ML-KEM, ECDHE |
| SecP256r1MLKEM768 | 4587 (0x11EB) | secp256r1 + ML-KEM-768 | 1249 | 1153 | 64 | ECDHE, ML-KEM |
| SecP384r1MLKEM1024 | 4589 (0x11ED) | secp384r1 + ML-KEM-1024 | 1665 | 1665 | 80 | ECDHE, ML-KEM |

IANA Recommended=Y only for X25519MLKEM768; the other two have
Recommended=N. **Recommended** is not a cryptographic implementation
approval, compliance attestation or policy Permit.

The obsoleted Kyber draft codepoints 25497 and 25498 are represented
explicitly as ObsoletedDraft. No experimental draft or unknown numeric
codepoint is treated as finalized ML-KEM. In particular, a standalone
ML-KEM-768 profile is a **constituent** and cannot satisfy an exact hybrid
TLS construction requirement.

## Evidence and evaluation boundaries

A TlsHybridObservation distinguishes configured Supported Groups from an
alleged negotiated NamedGroup. The latter is still an **untrusted source
claim**, not evidence of a TLS transcript or successfully validated shared
secrets. Every structurally successful outcome is called
StructurallyConsistentHybrid, **never Permit**.

A conservative assessment requires the claimed negotiated group to have
been offered, the origin to be Negotiated, both key share lengths to agree
with RFC 10024, and the explicit policy constraint to match the complete
construction. Unknown, draft, downgraded, mismatched or incomplete inputs
cannot produce a hybrid match. A requirement for a single PQ constituent
produces ComponentOnlyMatch rather than implying hybrid security.

Exact RFC 10024 profile sizes, component ordering and codepoints are tested
against independently checked-in golden vectors. No TLS record parsing,
certificate verification, ECDHE point validation, KEM ciphertext validity,
shared secret calculation, transcript proof, HKDF, source authentication or
access control occurs in the crate. The calling application must perform all
of those externally before treating any underlying cryptographic use as
verified and authorized.

## Developer verification

    cargo run -p pqc-kit --example tls_hybrid
    cargo test -p pqc-kit --test tls_hybrid --locked
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

Refs: [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html),
[RFC 9954](https://www.rfc-editor.org/rfc/rfc9954.html).
FOSS-459 integrates this into the complete normative corpus. Publishing
remains blocked by FOSS-464/466 and all package manifests stay unpublished.
