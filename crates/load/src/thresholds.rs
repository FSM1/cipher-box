//! Pass/fail bands for a dispatched run.
//!
//! The bands catch a collapse — latency from hundreds of milliseconds to
//! seconds, or a clean run turning into an error storm — not normal variance,
//! and staging's describe the 2-vCPU ceiling rather than headroom it does not
//! have. They read the `all` row, which spans provisioning and teardown too, so
//! they are a whole-run collapse detector and never a per-surface SLO.

use crate::metrics::OpSummary;
use crate::plan::{Scenario, Target};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Thresholds {
    pub p95_ms: f64,
    pub max_error_rate: f64,
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

/// Evaluate the `all` row. Throttling is reported but never breaches on its
/// own; a run where nothing succeeded does, since it measured nothing.
pub fn evaluate(thresholds: Thresholds, summaries: &[OpSummary]) -> Vec<String> {
    let Some(total) = summaries
        .iter()
        .find(|summary| summary.op == "all")
        .filter(|summary| summary.count > 0)
    else {
        return vec!["the run recorded no operations at all".to_owned()];
    };
    if total.ok == 0 {
        return vec![format!(
            "no operation succeeded: {} throttled, {} failed",
            total.throttled, total.failed
        )];
    }

    let mut breaches = Vec::new();
    if total.p95_ms > thresholds.p95_ms {
        breaches.push(format!(
            "p95 {:.0}ms exceeds the {:.0}ms band",
            total.p95_ms, thresholds.p95_ms
        ));
    }
    if total.error_rate() > thresholds.max_error_rate {
        breaches.push(format!(
            "error rate {:.2}% exceeds the {:.2}% band ({} of {} operations failed)",
            total.error_rate() * 100.0,
            thresholds.max_error_rate * 100.0,
            total.failed,
            total.count
        ));
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
        assert!(breaches[0].contains("p95"), "{}", breaches[0]);
    }

    #[test]
    fn an_error_storm_breaches() {
        let bands = thresholds_for(Scenario::Mixed, Target::Local);
        let rows = summaries(&[(Outcome::Failed, 10.0), (Outcome::Ok, 10.0)]);
        let breaches = evaluate(bands, &rows);
        assert_eq!(breaches.len(), 1);
        assert!(breaches[0].contains("error rate"), "{}", breaches[0]);
    }

    #[test]
    fn throttling_alongside_real_work_never_breaches() {
        let bands = thresholds_for(Scenario::Mixed, Target::Local);
        let mut samples = vec![(Outcome::Throttled, 10.0); 20];
        samples.push((Outcome::Ok, 10.0));
        assert!(evaluate(bands, &summaries(&samples)).is_empty());
    }

    #[test]
    fn a_wholly_throttled_run_breaches_because_it_measured_nothing() {
        let bands = thresholds_for(Scenario::Mixed, Target::Local);
        let breaches = evaluate(bands, &summaries(&[(Outcome::Throttled, 10.0); 20]));
        assert_eq!(breaches.len(), 1);
        assert!(
            breaches[0].contains("no operation succeeded"),
            "{}",
            breaches[0]
        );
    }

    #[test]
    fn a_run_that_recorded_nothing_breaches() {
        let bands = thresholds_for(Scenario::Mixed, Target::Local);
        let breaches = evaluate(bands, &summaries(&[]));
        assert_eq!(breaches.len(), 1);
        assert!(breaches[0].contains("no operations"), "{}", breaches[0]);
    }
}
