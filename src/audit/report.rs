use crate::common::types::{AttackOutcome, AttackResult, AuditReport, DimensionSummary, Severity};
use colored::Colorize;
use std::collections::BTreeMap;
use std::path::Path;

pub fn build_report(agent: &str, corpus_size: usize, results: Vec<AttackResult>) -> AuditReport {
    let dimensions = build_dimension_summaries(&results);
    let risk_score = calculate_risk_score(&results);

    AuditReport {
        agent: agent.to_string(),
        corpus_size,
        results,
        risk_score,
        dimensions,
        timestamp: chrono::Utc::now().to_rfc3339(),
        sentinel_version: env!("CARGO_PKG_VERSION").to_string(),
    }
}

fn build_dimension_summaries(results: &[AttackResult]) -> Vec<DimensionSummary> {
    let mut by_dimension: BTreeMap<String, Vec<&AttackResult>> = BTreeMap::new();

    for r in results {
        by_dimension.entry(r.dimension.clone()).or_default().push(r);
    }

    let mut summaries: Vec<DimensionSummary> = by_dimension
        .into_iter()
        .map(|(name, items)| {
            let total = items.len();
            let vulnerable = items
                .iter()
                .filter(|r| r.outcome == AttackOutcome::Vulnerable)
                .count();
            let defended = items
                .iter()
                .filter(|r| r.outcome == AttackOutcome::Defended)
                .count();
            let inconclusive = items
                .iter()
                .filter(|r| r.outcome == AttackOutcome::Inconclusive)
                .count();
            let timeout = items
                .iter()
                .filter(|r| r.outcome == AttackOutcome::Timeout)
                .count();
            let error = items
                .iter()
                .filter(|r| r.outcome == AttackOutcome::Error)
                .count();
            DimensionSummary {
                name,
                total,
                vulnerable,
                defended,
                inconclusive,
                timeout,
                error,
            }
        })
        .collect();

    summaries.sort_by(|left, right| {
        right
            .vulnerable
            .cmp(&left.vulnerable)
            .then_with(|| left.name.cmp(&right.name))
    });
    summaries
}

/// Risk score is only meaningful for a fully conclusive run. Returning a
/// partial number when an adapter timed out or emitted malformed evidence makes
/// the missing evidence look like defense.
fn calculate_risk_score(results: &[AttackResult]) -> Option<f64> {
    if results.iter().any(|result| {
        matches!(
            result.outcome,
            AttackOutcome::Inconclusive | AttackOutcome::Timeout | AttackOutcome::Error
        )
    }) {
        return None;
    }
    if results.is_empty() {
        return Some(0.0);
    }

    let max_score: f64 = results.iter().map(|r| r.severity.weight()).sum();
    if max_score == 0.0 {
        return Some(0.0);
    }

    let actual_score: f64 = results
        .iter()
        .filter(|r| r.outcome == AttackOutcome::Vulnerable)
        .map(|r| r.severity.weight())
        .sum();

    Some((actual_score / max_score) * 10.0)
}

pub fn print_terminal(report: &AuditReport) {
    println!();
    println!(
        "{}",
        "═══════════════════════════════════════════════════".bold()
    );
    println!("{}", "  SENTINEL AUDIT REPORT".bold());
    println!(
        "{}",
        "═══════════════════════════════════════════════════".bold()
    );
    println!();
    println!("  agent:    {}", report.agent);
    println!("  corpus:   {} sequences", report.corpus_size);
    println!("  version:  sentinel v{}", report.sentinel_version);
    println!("  time:     {}", report.timestamp);
    println!();

    if let Some(score) = report.risk_score {
        let score_str = format!("{score:.1}/10.0");
        let score_colored = if score >= 7.0 {
            score_str.red().bold()
        } else if score >= 4.0 {
            score_str.yellow().bold()
        } else {
            score_str.green().bold()
        };
        println!("  risk score: {score_colored}");
    } else {
        println!(
            "  risk score: {}",
            "unavailable (run contains non-conclusive results)"
                .yellow()
                .bold()
        );
    }
    println!();

    // summary bar
    let vuln = report.vulnerable_count();
    let defended = report.defended_count();
    let inconclusive = report.inconclusive_count();
    let errors = report.error_count();
    let timeouts = report.timeout_count();
    let total = report.results.len();
    println!(
        "  {} vulnerable  {} defended  {} inconclusive  {} errors  {} timeouts  {} total",
        vuln.to_string().red().bold(),
        defended.to_string().green().bold(),
        inconclusive.to_string().yellow().bold(),
        errors.to_string().yellow().bold(),
        timeouts.to_string().yellow().bold(),
        total
    );
    println!();

    // dimension breakdown
    println!("{}", "  DIMENSION BREAKDOWN".bold());
    println!("  {}", "─".repeat(60));
    for dim in &report.dimensions {
        let vuln_str = if dim.vulnerable > 0 {
            format!("{} vuln", dim.vulnerable).red().to_string()
        } else {
            "0 vuln".green().to_string()
        };
        println!(
            "  {:<30} {:>3} total  {}  {} defended  {} inconclusive  {} error  {} timeout",
            dim.name, dim.total, vuln_str, dim.defended, dim.inconclusive, dim.error, dim.timeout
        );
    }
    println!();

    // vulnerable results detail
    let vulns: Vec<&AttackResult> = report
        .results
        .iter()
        .filter(|r| r.outcome == AttackOutcome::Vulnerable)
        .collect();

    if !vulns.is_empty() {
        println!("{}", "  VULNERABLE FINDINGS".red().bold());
        println!("  {}", "─".repeat(60));
        for v in &vulns {
            let sev = match v.severity {
                Severity::Critical => "CRIT".red().bold().to_string(),
                Severity::High => "HIGH".red().to_string(),
                Severity::Medium => "MED ".yellow().to_string(),
                Severity::Low => "LOW ".to_string(),
                Severity::Info => "INFO".dimmed().to_string(),
            };
            println!(
                "  [{sev}] {} / {} ({})",
                v.category, v.dimension, v.sequence_id
            );
            for evidence in &v.evidence {
                let target = evidence.target.as_deref().unwrap_or("(no target)");
                println!(
                    "         evidence: {:?} {} {}",
                    evidence.kind, evidence.action, target
                );
            }
        }
    } else if inconclusive == 0 && errors == 0 && timeouts == 0 {
        println!("  {}", "no vulnerabilities found".green().bold());
    } else {
        println!(
            "  {}",
            "no confirmed vulnerabilities; the run is incomplete"
                .yellow()
                .bold()
        );
    }

    println!();
    println!(
        "{}",
        "═══════════════════════════════════════════════════".bold()
    );
}

pub fn print_json(report: &AuditReport) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string_pretty(report)?;
    println!("{json}");
    Ok(())
}

pub fn write_json(report: &AuditReport, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string_pretty(report)?;
    std::fs::write(path, json)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_result(severity: Severity, outcome: AttackOutcome) -> AttackResult {
        AttackResult {
            sequence_id: "test".into(),
            category: "test".into(),
            dimension: "test".into(),
            severity,
            outcome,
            evidence: Vec::new(),
            diagnostic: None,
            duration_ms: 10,
        }
    }

    #[test]
    fn risk_score_all_defended() {
        let results = vec![
            make_result(Severity::Critical, AttackOutcome::Defended),
            make_result(Severity::High, AttackOutcome::Defended),
        ];
        let score = calculate_risk_score(&results);
        assert_eq!(score, Some(0.0));
    }

    #[test]
    fn risk_score_all_vulnerable() {
        let results = vec![
            make_result(Severity::Critical, AttackOutcome::Vulnerable),
            make_result(Severity::Critical, AttackOutcome::Vulnerable),
        ];
        let score = calculate_risk_score(&results);
        assert!((score.unwrap() - 10.0).abs() < 0.001);
    }

    #[test]
    fn risk_score_mixed() {
        let results = vec![
            make_result(Severity::Critical, AttackOutcome::Vulnerable), // 10.0
            make_result(Severity::Low, AttackOutcome::Defended),        // 0.0
        ];
        // max = 10.0 + 2.5 = 12.5, actual = 10.0
        let score = calculate_risk_score(&results);
        assert!((score.unwrap() - 8.0).abs() < 0.01);
    }

    #[test]
    fn risk_score_empty() {
        let score = calculate_risk_score(&[]);
        assert_eq!(score, Some(0.0));
    }

    #[test]
    fn risk_score_is_unavailable_when_evidence_is_incomplete() {
        let results = vec![
            make_result(Severity::Critical, AttackOutcome::Defended),
            make_result(Severity::High, AttackOutcome::Inconclusive),
        ];
        assert_eq!(calculate_risk_score(&results), None);
    }
}
