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
    pub evidence: Option<String>,
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
}

/// aggregate report from a full audit run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub agent: String,
    pub corpus_size: usize,
    pub results: Vec<AttackResult>,
    pub risk_score: f64,
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
}
