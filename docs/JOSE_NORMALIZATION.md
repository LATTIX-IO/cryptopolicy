# FOSS-455 — RFC 9964 ML-DSA JOSE/JWK identity normalization

## Strict scope

The `pqc-jose` crate recognizes RFC 9964 public AKP JWKs and an independently
decoded JWS **protected** header with exact ML-DSA-44/65/87 alg matching.
It does not inspect complete JWS compact serialization, verify the signature,
prove issuer or key validity, validate a JWK thumbprint, authenticate the
caller-supplied protected header, perform cryptographic operations, or authorize
a CryptoPolicy operation. The API normalizes untrusted *metadata* only.

Input requirement: two bounded JSON byte slices (public JWK and a separately
extracted protected header). Both must agree on exact `alg` name. JWK `kty`
is exactly `AKP`; `alg` and unpadded canonical base64url `pub` are required.
The public key payload is structurally length-checked, not retained, and
never cryptographically decoded/validated as an ML-DSA public key. Exact raw
public-key octet lengths from RFC 9964 are 1312/1952/2592 for ML-DSA-44/65/87.

An optional JWK `use` must be `sig`; optional `key_ops` is restricted to
`["verify"]` for this public-only adapter. Optional protected `kid` must
match JWK `kid`. `typ`/`cty` are metadata only. Unknown fields, all `crit`
headers, and `b64` extension headers fail closed; `alg=none`, draft hybrid
names, noncanonical base64url, duplicate JSON members and mismatched
alg/kty/key purpose fail. Presence of **any** `priv` parameter is rejected:
RFC 9964 allows a 32-byte private seed, but this public-only adapter does
not accept or transform private material. Private key support would require
its own carefully audited API and threat model.

Per-call upper limits: 16,384 JWK JSON bytes and 2,048 protected-header JSON
bytes. Normalized report max: 8,192 bytes. Original JSON source bytes feed
a domain-separated SHA-256 correlation fingerprint; output contains no raw key
and both `signature_verified` and `key_validated` are always false.
Catalog profile identity is pinned to `pqc-kit` v1; catalog membership does
not imply provider validation, cryptographic correctness or policy approval.

## Safe Cryptopolicy projection

`JoseAlgorithmIdentity::to_untrusted_context` creates an explicit
`CryptoContext` with `FactOrigin::Inferred`, `verified=false`, and
`EvidenceQuality::Unverified`, independently of any untrusted report flags.
The current evaluator cannot promote this metadata into Permit. The caller
must independently authenticate source evidence and enforce Permit-only.

## Local reproduction

    cargo run -p pqc-jose --example normalize_jose
    cargo test -p pqc-jose --test identities --locked
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

Source: RFC 9964 (May 2026), Sections 3-7 and JWK IANA registrations:
https://www.rfc-editor.org/rfc/rfc9964.html

COSE (FOSS-457), hybrid TLS (FOSS-458) and complete runtime conformance
(FOSS-459) remain separate scope. No packages are published by this work.
