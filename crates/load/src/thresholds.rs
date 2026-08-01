//! Pass/fail bands for a dispatched run.
//!
//! Staging is one 2-vCPU VPS whose cores Kubo and someguy share
//! (blueprint/deploy.md), so its bands describe that ceiling rather than any
//! headroom the hardware does not have. They exist to catch a collapse — a
//! regression that takes latency from hundreds of milliseconds to seconds, or
//! turns a clean run into an error storm — not to police normal variance.

use crate::metrics::OpSummary;
use crate::plan::{Scenario, Target};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Thresholds {
    pub p95_ms: f64,
    pub max_error_rate: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Breach(pub String);

impl std::fmt::Display for Breach {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The band for a scenario on a target. Content ingest and gateway reads move
/// whole blocks through Kubo, so they get the widest latency band; the registry
/// and mailbox surfaces are Postgres round-trips and get a tighter one.
pub fn thresholds_for(scenario: Scenario, target: Target) -> Thresholds {
    let p95_ms = match (scenario, target) {
        (Scenario::ContentIngest | Scenario::GatewayRead, Target::Local) => 2_000.0,
        (Scenario::ContentIngest | Scenario::GatewayRead, Target::Staging) => 8_000.0,
        (_, Target::Local) => 1_000.0,
        (_, Target::Staging) => 4_000.0,
    };
    Thresholds {
        p95_ms,
        max_error_rate: 0.01,
    }
}

/// Evaluate the `all` row of a run. Throttling is reported but never breaches:
/// v2 removed the throttle bypass, so per-surface 429s are the API keeping its
/// promise, and a harness that failed on them would only be measuring the
/// buckets it was told about.
pub fn evaluate(thresholds: Thresholds, summaries: &[OpSummary]) -> Vec<Breach> {
    let Some(total) = summaries.iter().find(|s| s.op == "all") else {
        return vec![Breach("the run recorded no operations at all".to_owned())];
    };
    let mut breaches = Vec::new();
    if total.count == 0 {
        breaches.push(Breach("the run recorded no operations at all".to_owned()));
        return breaches;
    }
    if total.p95_ms > thresholds.p95_ms {
        breaches.push(Breach(format!(
            "p95 {:.0}ms exceeds the {:.0}ms band",
            total.p95_ms, thresholds.p95_ms
        )));
    }
    if total.error_rate() > thresholds.max_error_rate {
        breaches.push(Breach(format!(
            "error rate {:.2}% exceeds the {:.2}% band ({} of {} operations failed)",
            total.error_rate() * 100.0,
            thresholds.max_error_rate * 100.0,
            total.failed,
            total.count
        )));
    }
    breaches
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::{Collector, Outcome, Sample};

    fn summaries(samples: &[(Outcome, f64)]) -> Vec<OpSummary> {
        let mut collector = Collector::default();
        for (outcome, ms) in samples {
            collector.record(Sample::new("upload", *outcome, *ms));
        }
        collector.summarize(1_000.0)
    }

    #[test]
    fn staging_bands_are_wider_than_local_ones() {
        for scenario in Scenario::ALL {
            let local = thresholds_for(scenario, Target::Local);
            let staging = thresholds_for(scenario, Target::Staging);
            assert!(
                staging.p95_ms > local.p95_ms,
                "{} must not assume staging headroom it does not have",
                scenario.as_str()
            );
        }
    }

    #[test]
    fn a_healthy_run_breaches_nothing() {
        let bands = thresholds_for(Scenario::Mixed, Target::Local);
        let rows = summaries(&[(Outcome::Ok, 50.0), (Outcome::Ok, 90.0)]);
        assert!(evaluate(bands, &rows).is_empty());
    }

    #[test]
    fn a_latency_collapse_breaches() {
        let bands = thresholds_for(Scenario::Mixed, Target::Local);
        let rows = summaries(&[(Outcome::Ok, 50.0), (Outcome::Ok, 9_000.0)]);
        let breaches = evaluate(bands, &rows);
        assert_eq!(breaches.len(), 1);
        assert!(breaches[0].0.contains("p95"), "{}", breaches[0]);
    }

    #[test]
    fn an_error_storm_breaches() {
        let bands = thresholds_for(Scenario::Mixed, Target::Local);
        let rows = summaries(&[(Outcome::Failed, 10.0), (Outcome::Ok, 10.0)]);
        let breaches = evaluate(bands, &rows);
        assert_eq!(breaches.len(), 1);
        assert!(breaches[0].0.contains("error rate"), "{}", breaches[0]);
    }

    #[test]
    fn throttling_alone_never_breaches() {
        let bands = thresholds_for(Scenario::Mixed, Target::Local);
        let rows = summaries(&[(Outcome::Throttled, 10.0); 20]);
        assert!(evaluate(bands, &rows).is_empty());
    }

    #[test]
    fn a_run_that_recorded_nothing_breaches() {
        let bands = thresholds_for(Scenario::Mixed, Target::Local);
        let breaches = evaluate(bands, &summaries(&[]));
        assert_eq!(breaches.len(), 1);
        assert!(breaches[0].0.contains("no operations"), "{}", breaches[0]);
    }
}
