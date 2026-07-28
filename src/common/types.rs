use serde::{Deserialize, Serialize};

/// a single step in an attack sequence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStep {
    pub role: String,
    pub content: String,
}

/// what we expect the agent to do if vulnerable
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedBehavior {
    pub action: String,
    pub target_pattern: Option<String>,
}

/// metadata for an attack sequence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackMeta {
    pub id: String,
    pub category: String,
    pub dimension: String,
    pub severity: Severity,
    #[serde(default)]
    pub multi_turn: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn weight(&self) -> f64 {
        match self {
            Severity::Critical => 10.0,
            Severity::High => 7.5,
            Severity::Medium => 5.0,
            Severity::Low => 2.5,
            Severity::Info => 1.0,
        }
    }
}

/// a complete attack sequence from the corpus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSequence {
    pub meta: AttackMeta,
    pub steps: Vec<AttackStep>,
    pub expected_vulnerable_behavior: ExpectedBehavior,
}

/// result of running a single attack against an agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackResult {
    pub sequence_id: String,
    pub category: String,
    pub dimension: String,
    pub severity: Severity,
    pub outcome: AttackOutcome,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<AuditEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<String>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AttackOutcome {
    /// agent performed the vulnerable behavior
    Vulnerable,
    /// agent refused or did not perform the behavior
    Defended,
    /// attack timed out
    Timeout,
    /// error during execution
    Error,
    /// the agent completed, but the evidence is insufficient for a defended or
    /// vulnerable verdict
    Inconclusive,
}

/// A structured observation emitted by an agent adapter. Audit verdicts are
/// derived from these records, never from arbitrary stdout text.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvidence {
    pub kind: EvidenceKind,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Tool,
    Filesystem,
    Network,
}

/// aggregate report from a full audit run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub agent: String,
    pub corpus_size: usize,
    pub results: Vec<AttackResult>,
    /// Absent when any sequence is non-conclusive; reporting a numeric score
    /// over partial evidence would make adapter failures look safer.
    pub risk_score: Option<f64>,
    pub dimensions: Vec<DimensionSummary>,
    pub timestamp: String,
    pub sentinel_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DimensionSummary {
    pub name: String,
    pub total: usize,
    pub vulnerable: usize,
    pub defended: usize,
    pub inconclusive: usize,
    pub timeout: usize,
    pub error: usize,
}

impl AuditReport {
    pub fn vulnerable_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.outcome == AttackOutcome::Vulnerable)
            .count()
    }

    pub fn defended_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.outcome == AttackOutcome::Defended)
            .count()
    }

    pub fn inconclusive_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.outcome == AttackOutcome::Inconclusive)
            .count()
    }

    pub fn error_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.outcome == AttackOutcome::Error)
            .count()
    }

    pub fn timeout_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.outcome == AttackOutcome::Timeout)
            .count()
    }
}
