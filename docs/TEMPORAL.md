# FOSS-439: Temporal policy contracts

The rule temporal schedule is optional. Missing fields preserve existing v1 JSON and digest values. All input timestamps are UTC Unix milliseconds provided by the caller. No wall clock or timezone conversion occurs.

* effective_from: inclusive activation for any rule effect.
* expires_at: exclusive expiry for any rule effect.
* deprecated_from: inclusive advisory threshold, only for Warn.
* required_from: inclusive mandatory requirement threshold, only for Require.
* prohibited_from: inclusive prohibition threshold, only for Deny.

A matching Warn rule with deprecated_from appends a deprecation_warning reason and does not independently grant authorization. Matching Deny always takes precedence over other effects, regardless of rule order. Missing facts on active Deny or Require rules cannot become Permit. Invalid windows, empty time objects, and effect-incompatible temporal fields fail policy validation. The host must convert human-readable local times to UTC before storing them.

The demonstration uses synthetic fixture evidence, not authenticated operational state:

    cargo run -p cryptopolicy --example temporal_transition
    cargo test -p cryptopolicy --test temporal --locked

This increment performs no cryptographic operations, does not authenticate policy issuers, and does not implement time-bounded waivers or exceptions.
