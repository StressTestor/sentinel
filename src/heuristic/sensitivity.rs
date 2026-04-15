//! sensitivity level for tier 2 heuristic. maps the string config value
//! to a confidence threshold that controls false-positive rate.

use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sensitivity {
    Low,
    Medium,
    High,
}

impl Sensitivity {
    /// confidence threshold (0.0-1.0). a HeuristicResult with confidence
    /// strictly greater than this triggers escalation.
    pub const fn threshold(&self) -> f64 {
        match self {
            Sensitivity::Low => 0.7,
            Sensitivity::Medium => 0.3,
            Sensitivity::High => 0.15,
        }
    }
}

impl FromStr for Sensitivity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Ok(Sensitivity::Low),
            "medium" => Ok(Sensitivity::Medium),
            "high" => Ok(Sensitivity::High),
            other => Err(format!("unknown sensitivity '{other}' (expected low/medium/high)")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn medium_maps_to_threshold_0_3() {
        assert_eq!(Sensitivity::Medium.threshold(), 0.3);
    }

    #[test]
    fn low_is_least_sensitive() {
        assert!(Sensitivity::Low.threshold() > Sensitivity::Medium.threshold());
    }

    #[test]
    fn high_is_most_sensitive() {
        assert!(Sensitivity::High.threshold() < Sensitivity::Medium.threshold());
    }

    #[test]
    fn from_str_accepts_canonical() {
        assert_eq!("low".parse::<Sensitivity>().unwrap(), Sensitivity::Low);
        assert_eq!("medium".parse::<Sensitivity>().unwrap(), Sensitivity::Medium);
        assert_eq!("high".parse::<Sensitivity>().unwrap(), Sensitivity::High);
    }

    #[test]
    fn from_str_is_case_insensitive() {
        assert_eq!("MEDIUM".parse::<Sensitivity>().unwrap(), Sensitivity::Medium);
        assert_eq!("High".parse::<Sensitivity>().unwrap(), Sensitivity::High);
    }

    #[test]
    fn from_str_rejects_unknown() {
        let err = "paranoid".parse::<Sensitivity>().unwrap_err();
        assert!(err.contains("paranoid"));
        assert!(err.contains("low/medium/high"));
    }
}
