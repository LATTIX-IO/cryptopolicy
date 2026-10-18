# pqc-cose

Strict RFC 9964 ML-DSA COSE public AKP identity normalization. The crate is
metadata-only: no key validation, signature checking, COSE_Sign1 processing,
CWT verification, cryptographic use or authorization.

It accepts a canonical definite-length CBOR `COSE_Key` map and a **separately
extracted protected-header map**. A trusted COSE parser must supply that
protected header; this crate never accepts unprotected-header algorithm claims.

Run:

    cargo run -p pqc-cose --example normalize_cose
    cargo test -p pqc-cose --test identities --locked

See [contract](../../docs/COSE_NORMALIZATION.md). Source packages remain
unpublished (`publish = false`). Maintained by Lattix Technologies Corp.
Licensed under MIT OR Apache-2.0.
