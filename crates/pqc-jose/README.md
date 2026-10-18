# pqc-jose

Bounded RFC 9964 ML-DSA JOSE/JWK **public-key metadata** normalization.

Recognizes exact ML-DSA-44/65/87 AKP JWKs and matching JWS protected-header JSON. This does **not** perform signature/key validation, cryptographic operations, issuer authentication or policy authorization. Private JWK seed material and unknown/critical headers are deliberately rejected.

```sh
cargo run -p pqc-jose --example normalize_jose
cargo test -p pqc-jose --test identities --locked
```

See [contract](../../docs/JOSE_NORMALIZATION.md).

Maintained by Lattix Technologies Corp. Licensed under MIT OR Apache-2.0.
