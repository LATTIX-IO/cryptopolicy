//! Offline, fail-closed composition of pinned policy baselines and overlays.
//!
//! An effective Permit requires an explicit Permit from EVERY resolved layer.
//! Overlay Allow rules can therefore narrow, never broaden, a baseline.
//! Import resolution is supplied by the caller; this crate performs no I/O.

use crate::{
    ContractError, CryptoContext, DecisionOutcome, EvaluationTime, Limits, PolicyDecision,
    PolicyDigest, PolicyDocument, PolicyId, PolicyVersion, SchemaVersion, evaluate_with_limits,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Domain separation for effective-policy fingerprints; not a signature.
pub const EFFECTIVE_POLICY_DOMAIN_V1: &[u8] = b"cryptopolicy-effective-policy-v1\0";

/// Immutable identity of a dependency, pinned to semantic version and content.
///
/// The digest is the SHA-256 of canonical policy JSON, not its provenance.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyReference {
    /// Exact policy identifier.
    pub policy_id: PolicyId,
    /// Exact semantic version, never latest.
    pub version: PolicyVersion,
    /// Canonical policy bytes SHA-256 fingerprint.
    pub digest: PolicyDigest,
}

impl PolicyReference {
    /// Compute a strictly pinned reference from a validated policy document.
    pub fn from_document(document: &PolicyDocument) -> Result<Self, ContractError> {
        Ok(Self {
            policy_id: document.policy_id.clone(),
            version: document.version.clone(),
            digest: document.canonical_digest()?,
        })
    }
}

/// One explicitly pinned baseline and any number of mandatory overlay roots.
///
/// All roots and transitive imports are conjunctive, not policy overrides.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySet {
    /// Explicit policy-set wire contract version.
    pub schema_version: SchemaVersion,
    /// Required baseline policy identity.
    pub baseline: PolicyReference,
    /// Additional mandatory policies. Their ordering is not precedence.
    pub overlays: Vec<PolicyReference>,
}

impl PolicySet {
    /// Parse a strict versioned reference set with bounded JSON bytes.
    pub fn parse_json_with_limits(input: &[u8], limits: &Limits) -> Result<Self, CompositionError> {
        limits.check_json(input)?;
        let set: Self = serde_json::from_slice(input)
            .map_err(|_| CompositionError::InvalidSet("invalid_policy_set_json"))?;
        set.validate(limits)?;
        Ok(set)
    }

    /// Reject repeated roots and oversized overlay lists.
    pub fn validate(&self, limits: &Limits) -> Result<(), CompositionError> {
        limits.validate()?;
        let total = self
            .overlays
            .len()
            .checked_add(1)
            .ok_or(CompositionError::ResourceLimit("policy_nodes"))?;
        if total > limits.max_imports {
            return Err(CompositionError::ResourceLimit("policy_nodes"));
        }
        let mut references = BTreeSet::new();
        references.insert(self.baseline.clone());
        for overlay in &self.overlays {
            if !references.insert(overlay.clone()) {
                return Err(CompositionError::DuplicateReference);
            }
            if overlay.policy_id == self.baseline.policy_id {
                return Err(CompositionError::ReferenceConflict);
            }
        }
        Ok(())
    }
}

/// Caller-owned, preloaded policy document and its pinned dependencies.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyNode {
    /// Explicit resolver-node wire contract version.
    pub schema_version: SchemaVersion,
    /// Exact versioned policy document.
    pub document: PolicyDocument,
    /// Referenced policies, all required for authorization.
    pub imports: Vec<PolicyReference>,
}

/// Supplies preloaded documents to the compiler. Do not perform network I/O
/// during resolution if reproducibility or offline operation is required.
///
/// A missing reference must return Ok(None). Resolver errors abort
/// compilation, never yielding an incomplete effective policy.
pub trait PolicyResolver {
    /// Resolve one pinned reference or fail without fallback.
    fn resolve(&self, reference: &PolicyReference) -> Result<Option<PolicyNode>, CompositionError>;
}

impl<F> PolicyResolver for F
where
    F: Fn(&PolicyReference) -> Result<Option<PolicyNode>, CompositionError>,
{
    fn resolve(&self, reference: &PolicyReference) -> Result<Option<PolicyNode>, CompositionError> {
        self(reference)
    }
}

/// Typed, stable compilation failures distinct from runtime Deny.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompositionError {
    /// Invalid reference-set syntax or structure.
    InvalidSet(&'static str),
    /// A referenced policy was not provided.
    UnresolvedReference(PolicyId),
    /// A dependency points back to an active ancestor.
    CycleDetected,
    /// A caller provided the wrong ID/version for a pinned policy.
    IdentityMismatch,
    /// A policy document differs from its pinned content fingerprint.
    DigestMismatch,
    /// Same PolicyId appears with contradictory version/content identity.
    ReferenceConflict,
    /// Duplicate root or direct-import reference.
    DuplicateReference,
    /// Resource exhaustion or excessively deep dependency tree.
    ResourceLimit(&'static str),
    /// Invalid nested policy or context contract.
    Contract(ContractError),
}

impl fmt::Display for CompositionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for CompositionError {}

impl From<ContractError> for CompositionError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

/// One resolved, validated layer. All fields are read-only through the
/// EffectivePolicy component slice, not independently mutable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedPolicy {
    /// Pinned ID/version/content.
    pub reference: PolicyReference,
    /// Strict policy document used for this layer.
    pub document: PolicyDocument,
    /// Sorted immutable dependency graph edges.
    pub imports: Vec<PolicyReference>,
}

/// Atomically compiled, canonical, offline policy graph.
///
/// No component is returned on errors; no rule lists are flattened into an
/// unsafe union of Allow rules. Private fields prevent mutation of the
/// compiled snapshot after the effective fingerprint is computed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectivePolicy {
    set: PolicySet,
    components: Vec<ResolvedPolicy>,
    canonical_bytes: Vec<u8>,
    digest: PolicyDigest,
}

impl EffectivePolicy {
    /// The pinned baseline and sorted overlay identities.
    pub fn policy_set(&self) -> &PolicySet {
        &self.set
    }

    /// All resolved layers sorted by their pinned identity.
    pub fn components(&self) -> &[ResolvedPolicy] {
        &self.components
    }

    /// Domain-separated effective content fingerprint, not an attestation.
    pub fn digest(&self) -> &PolicyDigest {
        &self.digest
    }

    /// Versioned, length-prefixed canonical binary encoding.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Evaluate every required layer; a Permit requires ALL layers to Permit.
    ///
    /// Deny dominates Indeterminate, which dominates Permit. Per-layer decision
    /// reasons remain scoped to the pinned policy reference.
    pub fn evaluate(
        &self,
        context: &CryptoContext,
        explicit_time: EvaluationTime,
        limits: &Limits,
    ) -> Result<EffectiveDecision, CompositionError> {
        limits.validate()?;
        if self.components.len() > limits.max_imports {
            return Err(CompositionError::ResourceLimit("policy_nodes"));
        }
        let mut per_policy = Vec::with_capacity(self.components.len());
        let mut has_deny = false;
        let mut has_indeterminate = false;
        for component in &self.components {
            let decision =
                evaluate_with_limits(&component.document, context, explicit_time, limits)?;
            match decision.outcome {
                DecisionOutcome::Deny => has_deny = true,
                DecisionOutcome::Indeterminate => has_indeterminate = true,
                DecisionOutcome::Permit => {}
            }
            per_policy.push(ScopedDecision {
                reference: component.reference.clone(),
                decision,
            });
        }
        let outcome = if has_deny {
            DecisionOutcome::Deny
        } else if has_indeterminate {
            DecisionOutcome::Indeterminate
        } else {
            DecisionOutcome::Permit
        };
        let decision = EffectiveDecision {
            schema_version: SchemaVersion::V1,
            effective_policy_digest: self.digest.clone(),
            evaluated_at: explicit_time,
            outcome,
            components: per_policy,
        };
        let output = serde_json::to_vec(&decision)
            .map_err(|_| CompositionError::InvalidSet("decision_encoding"))?;
        limits.check_json(&output)?;
        Ok(decision)
    }
}

/// One reference-scoped result prevents RuleId collisions across policies.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedDecision {
    /// Pinned policy identity and digest.
    pub reference: PolicyReference,
    /// Existing v1 typed decision including ordered rule/evidence references.
    pub decision: PolicyDecision,
}

/// A stable aggregate outcome with provenance-preserving component decisions.
///
/// This is data, not an authenticated authorization token.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveDecision {
    /// Explicit v1 decision schema.
    pub schema_version: SchemaVersion,
    /// Canonical composed graph content SHA-256.
    pub effective_policy_digest: PolicyDigest,
    /// Caller-injected UTC Unix millisecond time.
    pub evaluated_at: EvaluationTime,
    /// Conjunction of every mandatory component's outcome.
    pub outcome: DecisionOutcome,
    /// Deterministically sorted policy-specific decisions.
    pub components: Vec<ScopedDecision>,
}

struct Walker<'a, R: PolicyResolver> {
    resolver: &'a R,
    limits: &'a Limits,
    active: BTreeSet<PolicyReference>,
    nodes: BTreeMap<PolicyId, ResolvedPolicy>,
    edges: usize,
    rules: usize,
    metadata: usize,
}

impl<R: PolicyResolver> Walker<'_, R> {
    fn visit(&mut self, reference: &PolicyReference, depth: usize) -> Result<(), CompositionError> {
        if depth > self.limits.max_import_depth {
            return Err(CompositionError::ResourceLimit("import_depth"));
        }
        if self.active.contains(reference) {
            return Err(CompositionError::CycleDetected);
        }
        if let Some(existing) = self.nodes.get(&reference.policy_id) {
            if existing.reference != *reference {
                return Err(CompositionError::ReferenceConflict);
            }
            return Ok(());
        }
        if self.nodes.len() >= self.limits.max_imports {
            return Err(CompositionError::ResourceLimit("policy_nodes"));
        }
        let mut node = self
            .resolver
            .resolve(reference)?
            .ok_or_else(|| CompositionError::UnresolvedReference(reference.policy_id.clone()))?;
        if node.document.policy_id != reference.policy_id
            || node.document.version != reference.version
        {
            return Err(CompositionError::IdentityMismatch);
        }
        let observed = node.document.canonical_digest()?;
        if observed != reference.digest {
            return Err(CompositionError::DigestMismatch);
        }
        node.document.validate_with_limits(self.limits)?;
        self.rules = self
            .rules
            .checked_add(node.document.rules.len())
            .ok_or(CompositionError::ResourceLimit("total_rules"))?;
        self.metadata = self
            .metadata
            .checked_add(node.document.metadata.len())
            .ok_or(CompositionError::ResourceLimit("total_metadata"))?;
        if self.rules > self.limits.max_rules {
            return Err(CompositionError::ResourceLimit("total_rules"));
        }
        if self.metadata > self.limits.max_metadata {
            return Err(CompositionError::ResourceLimit("total_metadata"));
        }
        if node.imports.len() > self.limits.max_imports {
            return Err(CompositionError::ResourceLimit("import_edges"));
        }
        node.imports.sort();
        if node.imports.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CompositionError::DuplicateReference);
        }
        self.edges = self
            .edges
            .checked_add(node.imports.len())
            .ok_or(CompositionError::ResourceLimit("import_edges"))?;
        if self.edges > self.limits.max_imports {
            return Err(CompositionError::ResourceLimit("import_edges"));
        }
        self.active.insert(reference.clone());
        // Insert before descending so alternate paths can identify inconsistent
        // pinned identities; the active set still detects cycles first.
        let imports = node.imports.clone();
        self.nodes.insert(
            reference.policy_id.clone(),
            ResolvedPolicy {
                reference: reference.clone(),
                document: node.document,
                imports,
            },
        );
        for imported in &node.imports {
            self.visit(imported, depth + 1)?;
        }
        self.active.remove(reference);
        Ok(())
    }
}

/// Atomic, offline compilation of a caller-supplied policy graph.
///
/// All policy IDs, versions and canonical content digests are pinned.
/// Duplicate IDs with different identity, missing imports, cycles and
/// resource-limit overflows fail without producing an EffectivePolicy.
pub fn compile_policy_set<R: PolicyResolver>(
    set: &PolicySet,
    resolver: &R,
    limits: &Limits,
) -> Result<EffectivePolicy, CompositionError> {
    set.validate(limits)?;
    let mut set = set.clone();
    set.overlays.sort();
    let mut walker = Walker {
        resolver,
        limits,
        active: BTreeSet::new(),
        nodes: BTreeMap::new(),
        edges: 0,
        rules: 0,
        metadata: 0,
    };
    walker.visit(&set.baseline, 0)?;
    for root in &set.overlays {
        walker.visit(root, 0)?;
    }
    let components: Vec<ResolvedPolicy> = walker.nodes.into_values().collect();
    let canonical_bytes = canonical_effective_bytes(&set, &components, limits)?;
    let hash = Sha256::digest(&canonical_bytes);
    let hex = hash.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let digest = PolicyDigest::try_from(hex)?;
    Ok(EffectivePolicy {
        set,
        components,
        canonical_bytes,
        digest,
    })
}

fn push_blob(buf: &mut Vec<u8>, blob: &[u8], max: usize) -> Result<(), CompositionError> {
    let total = buf
        .len()
        .checked_add(4)
        .and_then(|n| n.checked_add(blob.len()))
        .ok_or(CompositionError::ResourceLimit("effective_bytes"))?;
    if total > max {
        return Err(CompositionError::ResourceLimit("effective_bytes"));
    }
    let len = u32::try_from(blob.len())
        .map_err(|_| CompositionError::ResourceLimit("effective_bytes"))?;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(blob);
    Ok(())
}

fn push_count(buf: &mut Vec<u8>, count: usize, max: usize) -> Result<(), CompositionError> {
    let value =
        u32::try_from(count).map_err(|_| CompositionError::ResourceLimit("effective_bytes"))?;
    if buf.len().checked_add(4).is_none_or(|size| size > max) {
        return Err(CompositionError::ResourceLimit("effective_bytes"));
    }
    buf.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn ref_bytes(reference: &PolicyReference) -> Result<Vec<u8>, CompositionError> {
    serde_json::to_vec(reference).map_err(|_| CompositionError::InvalidSet("reference_encoding"))
}

fn canonical_effective_bytes(
    set: &PolicySet,
    nodes: &[ResolvedPolicy],
    limits: &Limits,
) -> Result<Vec<u8>, CompositionError> {
    let mut bytes = EFFECTIVE_POLICY_DOMAIN_V1.to_vec();
    let max = limits.max_json_bytes;
    if bytes.len() > max {
        return Err(CompositionError::ResourceLimit("effective_bytes"));
    }
    push_blob(&mut bytes, &ref_bytes(&set.baseline)?, max)?;
    push_count(&mut bytes, set.overlays.len(), max)?;
    for reference in &set.overlays {
        push_blob(&mut bytes, &ref_bytes(reference)?, max)?;
    }
    push_count(&mut bytes, nodes.len(), max)?;
    for node in nodes {
        push_blob(&mut bytes, &ref_bytes(&node.reference)?, max)?;
        push_count(&mut bytes, node.imports.len(), max)?;
        for imported in &node.imports {
            push_blob(&mut bytes, &ref_bytes(imported)?, max)?;
        }
        let policy = node.document.canonical_json_with_limits(limits)?;
        push_blob(&mut bytes, &policy, max)?;
    }
    Ok(bytes)
}
