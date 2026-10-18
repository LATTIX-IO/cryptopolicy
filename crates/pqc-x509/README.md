# pqc-x509

pqc-x509 is part of the Lattix open-source cryptopolicy workspace.

FOSS-452 provides strictly bounded RFC 9881 ML-DSA certificate signature
and RFC 9935 ML-KEM SPKI DER identity normalization. The library preserves
source/evidence references, exact OIDs and pinned pqc-kit names.

It DOES NOT parse whole certificates, verify signatures or chains, validate
key correctness, check revocation, authenticate external critical-extension
status, or produce a policy authorization. A trusted RFC 5280 extractor is
required before use.

Run cargo run -p pqc-x509 --example normalize_x509 and
cargo test -p pqc-x509 --test identities --locked.
See [the contract](../../docs/X509_NORMALIZATION.md).

Repository: https://github.com/LATTIX-IO/cryptopolicy

## Status

Early development. APIs prior to 1.0 may change.

## License

Licensed under either Apache-2.0 or MIT, at your option.
