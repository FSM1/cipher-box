//! Pass/fail bands for a dispatched run.
//!
//! The bands catch a collapse — latency from hundreds of milliseconds to
//! seconds, or a clean run turning into an error storm — not normal variance,
//! and staging's describe the 2-vCPU ceiling rather than headroom it does not
//! have. They read the `all` row, which spans provisioning and teardown too, so
//! they are a whole-run collapse detector and never a per-surface SLO. A
//! rotation-wave run reads its two measured rows instead
//! ([`Thresholds::max_of_rows`]).

use crate::metrics::OpSummary;
use crate::plan::{Scenario, Target};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Thresholds {
    pub p95_ms: f64,
    pub max_error_rate: f64,
    /// Rows whose maximum the band reads in place of the `all` row's p95: a
    /// rotation run has one sweep and one wave, and a p95 over its other
    /// samples hides a slow one.
    pub max_of_rows: &'static [&'static str],
}

/// The band for a scenario on a target. Content ingest and gateway reads move
/// whole blocks through Kubo, so they get the widest latency band; the registry
/// and mailbox surfaces are Postgres round-trips and get a tighter one.
pub fn thresholds_for(scenario: Scenario, target: Target) -> Thresholds {
    let p95_ms = match (scenario, target) {
        (Scenario::ContentIngest | Scenario::GatewayRead, Target::Local) => 2_000.0,
        (Scenario::ContentIngest | Scenario::GatewayRead, Target::Staging) => 8_000.0,
        // 16 nodes in RESULTS.md: the slowest sample, the populate, took 3.4 s.
        (Scenario::RotationWave, Target::Local) => 60_000.0,
        (Scenario::RotationWave, Target::Staging) => 120_000.0,
        (_, Target::Local) => 1_000.0,
        (_, Target::Staging) => 4_000.0,
    };
    Thresholds {
        p95_ms,
        // One failed sweep or wave is the fault the scenario exists to catch.
        max_error_rate: if scenario == Scenario::RotationWave {
            0.0
        } else {
            0.01
        },
        max_of_rows: if scenario == Scenario::RotationWave {
            &["sweep-converge", "name-wave"]
        } else {
            &[]
        },
    }
}

/// Evaluate the `all` row; a rotation run reads the rows of
/// [`Thresholds::max_of_rows`] for its latency band instead. Throttling is
/// reported but never breaches on its own; a run where nothing succeeded does,
/// since it measured nothing.
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
    if thresholds.max_of_rows.is_empty() {
        if total.p95_ms > thresholds.p95_ms {
            breaches.push(format!(
                "p95 {:.0}ms exceeds the {:.0}ms band",
                total.p95_ms, thresholds.p95_ms
            ));
        }
    } else {
        for name in thresholds.max_of_rows {
            match summaries.iter().find(|row| row.op == *name) {
                Some(row) if row.ok > 0 => {
                    if row.max_ms > thresholds.p95_ms {
                        breaches.push(format!(
                            "{name} max {:.0}ms exceeds the {:.0}ms band",
                            row.max_ms, thresholds.p95_ms
                        ));
                    }
                }
                _ => breaches.push(format!("the run recorded no successful {name}")),
            }
        }
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
    fn one_failed_rotation_sample_turns_the_run_red() {
        let bands = thresholds_for(Scenario::RotationWave, Target::Local);
        let mut run = sixteen_node_samples(734.0);
        // One failure in 106 samples stays below the default 1% band, so only
        // the 0% rotation band turns this run red.
        for _ in 0..80 {
            run.record(Sample::new("name-wave-node", Outcome::Ok, 35.0));
        }
        run.record(Sample::new("name-wave-node", Outcome::Failed, 0.0));
        let breaches = evaluate(bands, &run.summarize(1_000.0));
        assert_eq!(breaches.len(), 1);
        assert!(breaches[0].contains("error rate"), "{}", breaches[0]);
    }

    /// Shaped as one 16-node run: one sample per phase, 17 wave nodes.
    fn sixteen_node_samples(sweep_ms: f64) -> Collector {
        let mut collector = Collector::default();
        for (op, ms) in [
            ("engine-start", 209.0),
            ("populate", 3_447.0),
            ("link-mint", 898.0),
            ("read-cut", 66.0),
            ("sweep-converge", sweep_ms),
            ("sweep-last-reseal", 734.0),
            ("write-cut", 1_100.0),
            ("name-wave", 1_021.0),
        ] {
            collector.record(Sample::new(op, Outcome::Ok, ms));
        }
        for _ in 0..17 {
            collector.record(Sample::new("name-wave-node", Outcome::Ok, 35.0));
        }
        collector
    }

    fn sixteen_node_run(sweep_ms: f64) -> Vec<OpSummary> {
        sixteen_node_samples(sweep_ms).summarize(1_000.0)
    }

    #[test]
    fn a_sweep_at_the_convergence_budget_turns_a_full_run_red() {
        let bands = thresholds_for(Scenario::RotationWave, Target::Local);
        let budget = crate::rotation::CONVERGE_BUDGET.as_millis() as f64;
        let breaches = evaluate(bands, &sixteen_node_run(budget));
        assert_eq!(breaches.len(), 1);
        assert!(breaches[0].contains("sweep-converge"), "{}", breaches[0]);
    }

    #[test]
    fn a_full_run_with_every_sample_fast_breaches_nothing() {
        let bands = thresholds_for(Scenario::RotationWave, Target::Local);
        assert!(evaluate(bands, &sixteen_node_run(734.0)).is_empty());
    }

    #[test]
    fn a_rotation_run_with_no_sweep_row_is_red() {
        let bands = thresholds_for(Scenario::RotationWave, Target::Local);
        let mut rows = sixteen_node_run(734.0);
        rows.retain(|row| row.op != "sweep-converge");
        let breaches = evaluate(bands, &rows);
        assert_eq!(breaches.len(), 1);
        assert!(breaches[0].contains("sweep-converge"), "{}", breaches[0]);
    }

    #[test]
    fn a_rotation_run_with_an_empty_wave_row_is_red() {
        let bands = thresholds_for(Scenario::RotationWave, Target::Local);
        let mut rows = sixteen_node_run(734.0);
        let wave = rows
            .iter_mut()
            .find(|row| row.op == "name-wave")
            .expect("a name-wave row");
        (wave.count, wave.ok, wave.max_ms) = (0, 0, 0.0);
        let breaches = evaluate(bands, &rows);
        assert_eq!(breaches.len(), 1);
        assert!(breaches[0].contains("name-wave"), "{}", breaches[0]);
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
