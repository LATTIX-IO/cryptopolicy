# FOSS-457 — RFC 9964 COSE public ML-DSA normalization

## Accepted subset

The input is two separate byte slices: the canonical CBOR COSE_Key **map**
and the independently extracted protected-header **map bytes**. The caller
must obtain the latter from a real COSE_Sign1 protected bstr, not an
unprotected header or free-floating algorithm claim. No complete message,
signature or CWT is parsed by this adapter.

| Field | CBOR label | Accepted value |
|---|---:|---|
| COSE_Key kty | 1 | integer 7 (AKP) |
| COSE_Key alg | 3 | -48, -49, -50 |
| COSE_Key pub | -1 | bstr, 1312/1952/2592 bytes |
| COSE_Key priv | -2 | **always rejected** (secret input) |
| COSE_Key key_ops | 4 | absent or array [2] (verify only) |
| COSE_Key kid | 2 | optional bstr, at most 128 bytes |
| Protected alg | 1 | integer matching COSE_Key alg exactly |
| Protected kid | 4 | optional bstr matching COSE_Key kid |
| Protected crit | 2 | **always rejected**, even empty |
| Any other key/header label | — | rejected |

The algorithm map is -48=ML-DSA-44, -49=ML-DSA-65 and -50=ML-DSA-87.
Only these finalized RFC 9964 values can be mapped to the immutable
`pqc-kit` FIPS 204 catalog. This is a documentation identity,
**not a validated implementation or an authorization decision**.

The adapter uses a deliberately small CBOR decoder and enforces:
- Definitive lengths, minimal integer/length encoding, and RFC 8949
  **core deterministic** lexical ordering of encoded integer map labels.
- No duplicate labels, trailing CBOR items, indefinite length, floats, tags,
  text-valued labels, unchecked arbitrary nested values or unknown extensions.
- Up to 8 KiB COSE_Key bytes and 2 KiB protected-header map bytes.
  A maximum of 8 elements per CBOR array/map and a depth limit of 4.
- Exact public key byte length, without retaining the raw bytes in the
  normalized identity or validating their mathematical properties.
- A domain-separated SHA-256 correlation digest of original CBOR inputs,
  with independent caller-owned source/evidence references.
- Fixed normalized JSON wire version and conservative rejection of forged
  `signature_verified` and `key_validated` flags.

`to_untrusted_context` exports only `FactOrigin::Inferred`,
`verified=false`, and `EvidenceQuality::Unverified`. It cannot grant
policy Permit. The library never signs, verifies, authenticates or
enforces. A digest cannot establish cryptographic provenance.

## Reproduce

    cargo run -p pqc-cose --example normalize_cose
    cargo test -p pqc-cose --test identities --locked
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo +1.85.0 test --workspace --all-features --locked

The tests include three pinned RFC algorithm/size cases with independent
synthetic input hashes, duplicate/out-of-order labels, private label -2,
mismatched alg/kty, critical and unknown headers, invalid key_ops,
nonminimal integer/bstr lengths, key-id mismatches, malformed CBOR,
bounded resource abuse, downgraded/unverified projection and mutations.
The all-zero synthetic public keys are structural fixtures **not valid keys**.

## Deferred boundaries

FOSS-459 will add a full normative and runtime golden conformance corpus;
FOSS-458 will address finalized hybrid TLS profiles. This increment neither
enables any crate publication nor configures the protected release
environment (FOSS-464/466).

References: [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964.html),
[RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html),
[RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html).
