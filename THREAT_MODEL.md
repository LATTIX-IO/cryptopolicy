# Cryptopolicy threat model

**Status:** Normative security requirements. FOSS-435 implements a bounded single-target offline evaluator, but full scenario coverage is not yet proven. Companion corpus: `tests/fixtures/security/contract-v1.json`. Tracking: FOSS-426. Security controls must remain fail-closed at every implementation stage.

## 1. Scope and assets

Cryptopolicy is an offline Rust policy interpretation and deterministic decision library, not a cryptographic provider, discovery engine, identity provider, or PEP. Its asset is the correctness of decisions and explanations under untrusted policies, algorithm metadata, evidence, exception records and context. Protected assets: explicit policy authority, rule/requirement semantics, registry identities, exception scope and approval, key/provider assurance claims, source evidence, evaluator availability, canonical versions/digests, and confidentiality of sensitive request attributes.

### Actors and assumptions

- **Policy author / tenant admin:** Can submit policy documents and overlays; may err or act maliciously. A policy's issuer string is not authentication proof.
- **Profile maintainer:** Controls metadata about algorithm profiles, registry aliases and standards status; may supply stale or misleading metadata.
- **Caller / relying party:** Supplies operation, evaluation time and contextual facts; controls enforcement. A caller can misapply Deny/Indeterminate unless integration contract is explicit.
- **Inventory and telemetry importer:** Supplies observed/configured/inferred data, confidence, coverage and provenance; may be partial or attacker-controlled.
- **Key-management provider adapter:** Supplies claimed key properties and capabilities, which may not be independently attested.
- **Waiver approver / auditor:** Approves narrowly scoped deviations in an external governance system; exception strings do not establish authorization.
- **Adversarial parser input:** May contain aliases, critical attributes, duplicate keys, invalid encodings, depth bombs and oversize data.
- **Repository administrator / release operator:** Controls GitHub settings, CI workflows, environments and registry credentials; outside the authority of the policy evaluator. The controls established by FOSS-424 address part of this separate boundary.

Out-of-scope guarantees: cryptographic algorithm correctness, certificate chain validation, signature verification, key generation/use, caller identity proof, actual policy delivery authenticity, external provider attestation, and application-level enforcement. Those require their own security controls. No network/file/clock access belongs in deterministic evaluation.

## 2. Trust boundaries

| ID | Crossing | Untrusted side | Required control and owner |
|---|---|---|---|
| TB-01 | Serialized policy/issuer -> validated policy | Policy author and policy distributor | Strict schema/default, caller-side authenticity, bounded input (FOSS-429/433) |
| TB-02 | Operation/time/context -> evaluation | Requesting caller | Explicit time, missing-fact handling, typed outcome (FOSS-435/439) |
| TB-03 | Base policy/import/overlay -> effective policy | Environment/application policy author | Cycle/conflict detection, monotonic mandatory requirements (FOSS-437) |
| TB-04 | Exception approval record -> waiver application | External approval system | Trusted authorization, exact scope, expiry and compensating requirements (FOSS-443) |
| TB-05 | Registry/profile metadata -> normalized identity | External profile maintainer | Immutable versioned identifiers, codepoint provenance, exact parameters (FOSS-445/458) |
| TB-06 | Cryptomap/third-party inventory -> observed facts | Collectors and telemetry | Keep provenance/confidence and absence/configured/observed distinctions (FOSS-447) |
| TB-07 | Keymesh/provider metadata -> capability assertions | Provider/transport | Authenticity/attestation, no unsupported assumption (FOSS-449) |
| TB-08 | X.509/JOSE/COSE bytes -> policy facts | Potentially malicious input | Bounded parsing and explicit unsupported critical profiles (FOSS-452/455/457) |
| TB-09 | Decision diagnostics -> tracing/audit sink | Consumer-provided metadata | Redaction/allowlisting, stable codes, bounded output (FOSS-445/460) |
| TB-10 | PolicyDecision -> enforcement action | Application or key provider | Permit-only enforcement, reject errors and missing results (FOSS-440) |

## 3. Decision and authorization invariants

Input loading/validation precedes evaluation. Invalid policy, untrusted required issuer/authentication facts, unsupported mandatory schema extensions, unresolved imports or exceeded limits produce **typed errors** and cannot be used as a Permit. A matching explicit non-waived Deny is authoritative. An Allow can authorize only when all mandatory constraints and exact named profiles are satisfied. Incomplete relevant facts produce Indeterminate unless a separately definitive denial already applies. A no-match result follows the policy's explicitly declared default; secure construction defaults to Deny. Warning/Audit effects must never authorize.

**API distinction:** `Ok(Decision::Deny)` is a normal policy evaluation outcome; `Ok(Decision::Indeterminate)` is also a non-authorizing outcome; `Err(InvalidPolicy/UnsupportedSchema/...)` means reliable evaluation did not complete. Every enforcement caller must block protected actions for all states other than a valid Permit. Whether to return Deny or Indeterminate on a particular missing attribute must be specified by validated policy semantics and recorded as a stable reason code, never silently guessed.

### Normative security invariants
- **SEC-001** — Every policy declares an explicit default effect; builders choose Deny. Owner: FOSS-429.
- **SEC-002** — A matching non-waived Deny dominates Allow; unmatched requests never implicitly Permit. Owner: FOSS-435.
- **SEC-003** — Indeterminate, validation errors and evaluation errors are non-authorizing at enforcement boundaries. Owner: FOSS-435.
- **SEC-004** — Unknown mandatory facts cannot satisfy requirements or produce Permit. Owner: FOSS-435.
- **SEC-005** — Composition is monotonic for mandatory baseline requirements; overlays cannot silently weaken policy. Owner: FOSS-437.
- **SEC-006** — Waivers are explicit, attributable, authorized, precisely scoped, time-bounded and limited to explicitly waivable controls. Owner: FOSS-443.
- **SEC-007** — Temporal semantics require injected evaluation time with deterministic boundary handling. Owner: FOSS-439.
- **SEC-008** — Algorithm, operation, parameters and exact profile identity must be checked; no approximate alias or security-category downgrade. Owner: FOSS-445.
- **SEC-009** — Draft, experimental, deprecated and unknown profiles never inherit standardized or approved status by inference. Owner: FOSS-445.
- **SEC-010** — Observed, configured, negotiated, inferred and absent evidence remain distinct; partial coverage never proves compliance. Owner: FOSS-447.
- **SEC-011** — Provider capability, origin, exportability and protection assurance must be trustworthy and complete for required decisions. Owner: FOSS-449.
- **SEC-012** — Untrusted format identifiers and data require bounded parsing and explicit unsupported results, never fallback to a similar profile. Owner: FOSS-452.
- **SEC-013** — Import cycles, unresolved imports and conflicting exact mandatory requirements fail before Permit. Owner: FOSS-437.
- **SEC-014** — Policy, selector, import, exception, batch, adapter and diagnostic resources are bounded. Owner: FOSS-433.
- **SEC-015** — Diagnostics and observability disclose stable codes and safe identifiers, not credentials, private key material or raw sensitive context. Owner: FOSS-45.
- **SEC-016** — Canonical decisions, reasons and policy/registry identities are reproducible from the same explicit inputs. Owner: FOSS-435.
- **SEC-017** — Downstream enforcement must authorize exclusively on a valid Permit; other results block protected operations. Owner: FOSS-440.
- **SEC-018** — Hybrid and composite transition policy references a named exact construction, never a generic hybrid flag. Owner: FOSS-458.
- **SEC-019** — Unknown security-critical schema fields and unsupported versions are rejected rather than ignored. Owner: FOSS-429.
- **SEC-020** — Policy issuer claims and exception approval metadata are not proof of authenticity; caller trust must be established. Owner: FOSS-429.

### Order of evaluation (target contract, not implemented yet)

1. Validate schema, imports, profile/status references, limits, exception trust prerequisites and explicit time. On error, no authorization.
2. Canonicalize and compose baseline/overlays transactionally. Hard constraints accumulate; any unresolved contradiction blocks.
3. Match typed selectors without evaluating untrusted code. Missing mandatory facts and unknown potentially decisive selectors are treated explicitly.
4. Apply authoritative matching Deny. Unwaivable Deny cannot be masked by a later Allow or an exception.
5. Validate each eligible waiver against exact RuleId, target scope, approver trust, effective/expiry, status and compensating requirements. Never infer approval from caller-provided strings.
6. Authorize only on explicit matched allowance with all required evidence and requirements satisfied. Otherwise return Deny or Indeterminate as specified.
7. Return stable ordered reason codes, references to matched rules, policy/registry versions/digests and explicit evaluation time. Never include raw secrets.

## 4. Highest-risk abuse trees

**Unauthorized Permit**
1. Supply an allow-first rule file so a later explicit Deny is ignored; defend with order-independent Deny precedence (SEC-002).
2. Omit a key protection or assured provider fact; defend by Indeterminate (SEC-003/004/011).
3. Substitute a nearly named algorithm/weak parameter or mark draft as standardized; defend by exact profile identity and status (SEC-008/009/018).
4. Supply a broad/expired waiver or forge its approver string; defend through exact-scope, caller-trusted authorization (SEC-006/020).
5. Supply partial Cryptomap inventory and assert absence of crypto as compliance; defend by evidence coverage distinction (SEC-010).

**Policy compilation bypass**
1. Remove inherited restrictions through overlay; reject conflicting or weaker effective policies (SEC-005).
2. Build cyclic imports or deeply nested documents to suppress checks; bound imports and reject cycles (SEC-013/014).
3. Submit an unknown security-critical schema field, e.g. a fictitious override setting; reject unsupported schema (SEC-019).

**Diagnostic and availability compromise**
1. Submit huge policies, inputs, deep imports or excessive diagnostic requests; enforce resource limits before allocation (SEC-014).
2. Include private material in context hoping it will be reflected in tracing/error text; redact by default (SEC-015).
3. Feed malformed critical X.509/JOSE/COSE metadata and rely on heuristic fallback; reject/mark unsupported rather than promoting to valid algorithms (SEC-012).

## 5. Threat register and test linkage

| Threat | Severity | Boundary | Abuse objective | Invariant |
|---|---|---|---|---|
| THR-001 — Unauthorized default or rule-order bypass | critical | TB-01 | Unset default, allow-before-deny, or nonmatching rules become authorization | SEC-001 |
| THR-002 — Missing policy facts or enforcement bypass | critical | TB-02 | Uncertainty or errors mapped to Permit by consumer | SEC-003 |
| THR-003 — Missing required attributes | critical | TB-02 | Missing HSM assurance or key attributes deemed compliant | SEC-004 |
| THR-004 — Baseline override or conflict | critical | TB-03 | Environment/application overlays silently remove mandatory constraints | SEC-005 |
| THR-005 — Exception/waiver scope inflation | critical | TB-04 | Broad or expired exceptions authorize outside intended scope | SEC-006 |
| THR-006 — Temporal context tampering | high | TB-02 | Implicit wall-clock or ambiguous deadline permits deprecated configuration | SEC-007 |
| THR-007 — Algorithm/profile downgrade | critical | TB-05 | Algorithm family or alias accepted with weaker parameters | SEC-008 |
| THR-008 — Draft profile masquerades as standard | high | TB-05 | Experimental identifier silently classified as approved | SEC-009 |
| THR-009 — Evidence laundering | critical | TB-06 | Installed library/configured protocol passed as observed use | SEC-010 |
| THR-010 — Provider assurance substitution | critical | TB-07 | Self-asserted protection, origin or exportability satisfies mandatory rule | SEC-011 |
| THR-011 — Format parser confusion | critical | TB-08 | Invalid critical identifiers normalized to known safe profile | SEC-012 |
| THR-012 — Import cycle or inconsistent policies | high | TB-03 | Unbounded imports or contradictory hard requirements mask conflict | SEC-013 |
| THR-013 — Resource exhaustion | high | TB-01 | Huge inputs, import depth or diagnostics exhaust CPU/memory | SEC-014 |
| THR-014 — Sensitive diagnostic leakage | high | TB-09 | Secrets or sensitive context exposed through errors/traces | SEC-015 |
| THR-015 — Nondeterminism or audit evasion | high | TB-05 | Reordered rules/profile metadata yield different results | SEC-016 |
| THR-016 — Non-permit converted to allow | critical | TB-10 | Application treats Indeterminate/Error as success | SEC-017 |
| THR-017 — Ambiguous hybrid construction | high | TB-05 | Boolean hybrid tag accepted without named standardized construction | SEC-018 |
| THR-018 — Unknown critical schema input | critical | TB-01 | Unknown mandatory rule field is ignored | SEC-019 |
| THR-019 — Policy origin spoofing | critical | TB-01 | Issuer string or unsigned waiver accepted as trusted authority | SEC-020 |
| THR-020 — Policy priority bypass | critical | TB-01 | Rule order erases matching Deny | SEC-002 |

## 6. Evidence handling, normalization and protocol scope

Observed-use evidence is not interchangeable with a dependency declaration, a configured TLS cipher list, a test-only capability, or an uninspected source. Context projection must preserve source ID, observation time, direct/inferred status, conflicts, and partial coverage. Alias normalization must preserve original untrusted identifiers and bound canonical registry/profile versions. Neither X.509/JOSE/COSE identification nor algorithm-name recognition implies the implementation has authenticated, verified signatures, or satisfied FIPS validation.

## 7. Limits, diagnostics and temporal controls

Resource budgets to be designed in FOSS-433 include maximum policy bytes, nesting, number of rules and conditions, import depth and count, exceptions, normalized registry entries, adapter object size, batch size and diagnostics count/length. Large inputs fail with typed `ResourceLimitExceeded`, without partial Permit or unbounded allocation. All temporal decisions accept injected evaluation timestamps; precise inclusive/exclusive cutoffs must be documented and golden-tested. Emit only policy/digest reference IDs, reason/error codes and safe bounded counters by default; never log key bytes, credentials, raw tokens or unredacted context.

## 8. Verification and honest maturity status

The JSON corpus is a **contract and adversarial fixture specification**, not full executable engine conformance: the repository contains the versioned FOSS-435 single-context evaluator, but it has not yet been bound to every golden fixture. The linter validates fixture integrity, threat coverage, negative non-Permit expectations, and version/ID stability. An optional strict results comparator can match actual results supplied by a future evaluator, and fails on missing, extra or altered outcomes. No expected-output fixture may be automatically regenerated in CI. `runtime_conformance_verified` remains false for the complete normative corpus until all cases are independently mapped and CI executes them against the evaluator (FOSS-459). No false green behavior test is accepted.

Future required handoff: FOSS-429 implements schema/validation; FOSS-433 implements bounds; FOSS-434 typed predicates; FOSS-435 decision runtime; FOSS-437 composition; FOSS-439 time; FOSS-443 waivers; FOSS-445 registry; FOSS-447 observed evidence; FOSS-449 provider capability; FOSS-452/455/457 format adapters; FOSS-459 canonical conformance. Owners must connect each applicable golden CASE-* to actual public API tests. FOSS-426 closes only when the normative model, fixture linter, and regression checks pass, not when future runtime tests are green.

## 9. Release governance boundary

FOSS-424 disables bootstrapped package publishing and separates release PRs from a manually dispatched publish workflow. GitHub environment names do **not** create approval policy. A repository administrator must configure required environment reviewers, independent approval where supported, deployment branch restrictions, and scoped registry credentials before enabling the release variable. The repository ruleset's required Rust checks alone do not establish human review. The security contract protects future policy semantics; it does not substitute for release environment administration.

## 10. Developer test command

From the repository root, use `python3 scripts/security_contract.py --lint` followed by `python3 -m unittest discover -s tests -p 'test_security_contract.py' -v`. For future runtime verification, supply `--results path/to/evaluator-results.json`; results must include exactly one output for each fixture and match the checked-in expected result. Never enable a fake-pass fallback if runtime output is missing.

## FOSS-437 baseline and import security boundary

The offline FOSS-437 EffectivePolicy graph compiles references pinned by policy ID,
exact version and canonical content digest. Unresolved imports, import cycles,
conflicting policy versions and resource-exhaustion limits reject the entire
compile. Every imported policy is mandatory; a Permit requires Permit in all
layers so a permissive overlay cannot override a baseline Deny. The digest is
not provenance authentication, and the FOSS-435 single-fact and untrusted
issuer/evidence limitations still apply. Complete runtime correspondence to
the 33 golden threat-contract cases remains a separate FOSS-459 requirement.

## FOSS-445 algorithm catalog trust boundary

The pqc-kit registry describes published algorithm specifications and named parameter sets, not authenticated implementations or user authorization. Aliases, unknown/pre-standard names, incorrect operation classes, parameter mismatch, and nonstandard lifecycle records do not authorize use. The FOSS-435 evaluator stays conservative; FOSS-447/449 must add authenticated evidence and provider integration, and FOSS-459 still owns the full 33-case runtime conformance gate.

## FOSS-447 third-party observed-fact trust boundary

The assessment adapter preserves direct/negotiated, configured, dependency, inferred and provider-capability sources distinctly. It requires an independently authenticated exact source/evidence/snapshot/use-site/session binding before projecting one fact at a time to FOSS-435. High confidence, raw source_quality or an imported verified flag are not sufficient. Incomplete/uninspected coverage, conflicting observations, missing facts, bad parameters and untrusted evidence never authorize. Definitive policy Deny still dominates. Original IDs and confidence are returned separately from the policy verdict. FOSS-459 still owns the complete 33-case normative conformance gate.

## FOSS-449 Keymesh-style provider assurance boundary

The provider capability assessment contract distinguishes advertised algorithm/key capabilities from observed crypto use and from an authenticated PolicyDecision. Exact provider, catalog identity, parameters, key origin/exportability, HSM protection and evidence timestamps are mandatory whenever required by policy. Caller-provided independently authenticated source and assurance verification gates are distinct; provider claims are never self-trusting. Unreviewed algorithms, explicit authenticated downgrade/forbidden capability Deny; missing, stale, unknown, unauthenticated or conflicting claims remain nonauthorizing. No private key material, provider I/O, registry release or automatic authorization is included. FOSS-459 and FOSS-466 remain separate conformance/publishing gates.
