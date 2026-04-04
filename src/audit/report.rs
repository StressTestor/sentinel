use crate::common::types::{AttackOutcome, AttackResult, AuditReport, DimensionSummary, Severity};
use colored::Colorize;
use std::collections::HashMap;
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
    let mut by_dimension: HashMap<String, Vec<&AttackResult>> = HashMap::new();

    for r in results {
        by_dimension
            .entry(r.dimension.clone())
            .or_default()
            .push(r);
    }

    let mut summaries: Vec<DimensionSummary> = by_dimension
        .into_iter()
        .map(|(name, items)| {
            let total = items.len();
            let vulnerable = items.iter().filter(|r| r.outcome == AttackOutcome::Vulnerable).count();
            let defended = items.iter().filter(|r| r.outcome == AttackOutcome::Defended).count();
            let timeout = items.iter().filter(|r| r.outcome == AttackOutcome::Timeout).count();
            let error = items.iter().filter(|r| r.outcome == AttackOutcome::Error).count();
            DimensionSummary { name, total, vulnerable, defended, timeout, error }
        })
        .collect();

    summaries.sort_by(|a, b| b.vulnerable.cmp(&a.vulnerable));
    summaries
}

/// risk score: weighted sum of vulnerable results / max possible score.
/// 0.0 = completely safe, 10.0 = everything is on fire.
fn calculate_risk_score(results: &[AttackResult]) -> f64 {
    if results.is_empty() {
        return 0.0;
    }

    let max_score: f64 = results.iter().map(|r| r.severity.weight()).sum();
    if max_score == 0.0 {
        return 0.0;
    }

    let actual_score: f64 = results
        .iter()
        .filter(|r| r.outcome == AttackOutcome::Vulnerable)
        .map(|r| r.severity.weight())
        .sum();

    (actual_score / max_score) * 10.0
}

pub fn print_terminal(report: &AuditReport) {
    println!();
    println!("{}", "═══════════════════════════════════════════════════".bold());
    println!("{}", "  SENTINEL AUDIT REPORT".bold());
    println!("{}", "═══════════════════════════════════════════════════".bold());
    println!();
    println!("  agent:    {}", report.agent);
    println!("  corpus:   {} sequences", report.corpus_size);
    println!("  version:  sentinel v{}", report.sentinel_version);
    println!("  time:     {}", report.timestamp);
    println!();

    // risk score with color
    let score_str = format!("{:.1}/10.0", report.risk_score);
    let score_colored = if report.risk_score >= 7.0 {
        score_str.red().bold()
    } else if report.risk_score >= 4.0 {
        score_str.yellow().bold()
    } else {
        score_str.green().bold()
    };
    println!("  risk score: {score_colored}");
    println!();

    // summary bar
    let vuln = report.vulnerable_count();
    let defended = report.defended_count();
    let total = report.results.len();
    println!(
        "  {} vulnerable  {} defended  {} total",
        vuln.to_string().red().bold(),
        defended.to_string().green().bold(),
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
            "  {:<30} {:>3} total  {}  {} defended",
            dim.name, dim.total, vuln_str, dim.defended
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
            if let Some(evidence) = &v.evidence {
                let preview: String = evidence.chars().take(120).collect();
                println!("         evidence: {}", preview.dimmed());
            }
        }
    } else {
        println!("  {}", "no vulnerabilities found".green().bold());
    }

    println!();
    println!("{}", "═══════════════════════════════════════════════════".bold());
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
            evidence: None,
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
        assert_eq!(score, 0.0);
    }

    #[test]
    fn risk_score_all_vulnerable() {
        let results = vec![
            make_result(Severity::Critical, AttackOutcome::Vulnerable),
            make_result(Severity::Critical, AttackOutcome::Vulnerable),
        ];
        let score = calculate_risk_score(&results);
        assert!((score - 10.0).abs() < 0.001);
    }

    #[test]
    fn risk_score_mixed() {
        let results = vec![
            make_result(Severity::Critical, AttackOutcome::Vulnerable), // 10.0
            make_result(Severity::Low, AttackOutcome::Defended),        // 0.0
        ];
        // max = 10.0 + 2.5 = 12.5, actual = 10.0
        let score = calculate_risk_score(&results);
        assert!((score - 8.0).abs() < 0.01);
    }

    #[test]
    fn risk_score_empty() {
        let score = calculate_risk_score(&[]);
        assert_eq!(score, 0.0);
    }
}
