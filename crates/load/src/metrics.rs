//! Per-operation samples and their aggregation. Rate limiting is counted apart
//! from failure — see `outcome_of` in `runner.rs`.

/// What one operation did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Throttled,
    Failed,
}

#[derive(Debug, Clone)]
pub struct Sample {
    pub op: &'static str,
    pub outcome: Outcome,
    pub latency_ms: f64,
    pub bytes: u64,
    pub detail: Option<String>,
}

impl Sample {
    pub fn new(op: &'static str, outcome: Outcome, latency_ms: f64) -> Self {
        Self {
            op,
            outcome,
            latency_ms,
            bytes: 0,
            detail: None,
        }
    }

    pub fn with_bytes(mut self, bytes: u64) -> Self {
        self.bytes = bytes;
        self
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

#[derive(Debug, Default)]
pub struct Collector {
    samples: Vec<Sample>,
}

impl Collector {
    pub fn record(&mut self, sample: Sample) {
        self.samples.push(sample);
    }

    pub fn absorb(&mut self, other: Collector) {
        self.samples.extend(other.samples);
    }

    /// Aggregate into one summary per operation plus an all-operations total,
    /// with `wall_ms` the elapsed run time that throughput is divided by.
    pub fn summarize(&self, wall_ms: f64) -> Vec<OpSummary> {
        let mut ops: Vec<&'static str> = Vec::new();
        for sample in &self.samples {
            if !ops.contains(&sample.op) {
                ops.push(sample.op);
            }
        }
        let mut out: Vec<OpSummary> = ops
            .into_iter()
            .map(|op| OpSummary::of(op, self.samples.iter().filter(|s| s.op == op), wall_ms))
            .collect();
        out.push(OpSummary::of("all", self.samples.iter(), wall_ms));
        out
    }

    /// The first failure detail, for a run that produced no usable numbers.
    pub fn first_failure(&self) -> Option<&str> {
        self.samples
            .iter()
            .find(|s| s.outcome == Outcome::Failed)
            .and_then(|s| s.detail.as_deref())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpSummary {
    pub op: &'static str,
    pub count: u64,
    pub ok: u64,
    pub throttled: u64,
    pub failed: u64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
    pub ops_per_sec: f64,
    pub bytes: u64,
    pub bytes_per_sec: f64,
    /// The first failure this operation saw — the reason behind the counts.
    pub first_failure: Option<String>,
}

impl OpSummary {
    fn of<'a>(op: &'static str, samples: impl Iterator<Item = &'a Sample>, wall_ms: f64) -> Self {
        let mut latencies: Vec<f64> = Vec::new();
        let (mut ok, mut throttled, mut failed, mut bytes) = (0u64, 0u64, 0u64, 0u64);
        let mut first_failure = None;
        for sample in samples {
            latencies.push(sample.latency_ms);
            bytes += sample.bytes;
            match sample.outcome {
                Outcome::Ok => ok += 1,
                Outcome::Throttled => throttled += 1,
                Outcome::Failed => {
                    failed += 1;
                    if first_failure.is_none() {
                        first_failure.clone_from(&sample.detail);
                    }
                }
            }
        }
        latencies.sort_by(f64::total_cmp);
        let count = latencies.len() as u64;
        let seconds = (wall_ms / 1000.0).max(f64::MIN_POSITIVE);
        Self {
            op,
            count,
            ok,
            throttled,
            failed,
            p50_ms: percentile(&latencies, 0.50),
            p95_ms: percentile(&latencies, 0.95),
            p99_ms: percentile(&latencies, 0.99),
            max_ms: latencies.last().copied().unwrap_or(0.0),
            ops_per_sec: count as f64 / seconds,
            bytes,
            bytes_per_sec: bytes as f64 / seconds,
            first_failure,
        }
    }

    pub fn error_rate(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.failed as f64 / self.count as f64
        }
    }
}

/// Nearest-rank percentile over an ascending slice. Empty input is 0.0 — a
/// summary with no samples reports no latency rather than a sentinel that a
/// threshold could accidentally pass.
pub fn percentile(sorted_ascending: &[f64], quantile: f64) -> f64 {
    if sorted_ascending.is_empty() {
        return 0.0;
    }
    let rank = (quantile * sorted_ascending.len() as f64).ceil() as usize;
    let index = rank.saturating_sub(1).min(sorted_ascending.len() - 1);
    sorted_ascending[index]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(op: &'static str, outcome: Outcome, ms: f64) -> Sample {
        Sample::new(op, outcome, ms)
    }

    #[test]
    fn percentiles_use_nearest_rank() {
        let values: Vec<f64> = (1..=100).map(|v| v as f64).collect();
        assert_eq!(percentile(&values, 0.50), 50.0);
        assert_eq!(percentile(&values, 0.95), 95.0);
        assert_eq!(percentile(&values, 0.99), 99.0);
    }

    #[test]
    fn a_single_sample_is_every_percentile() {
        assert_eq!(percentile(&[7.0], 0.50), 7.0);
        assert_eq!(percentile(&[7.0], 0.99), 7.0);
    }

    #[test]
    fn an_empty_series_has_no_latency() {
        assert_eq!(percentile(&[], 0.95), 0.0);
    }

    #[test]
    fn outcomes_are_counted_in_three_separate_buckets() {
        let mut collector = Collector::default();
        collector.record(sample("upload", Outcome::Ok, 10.0));
        collector.record(sample("upload", Outcome::Throttled, 5.0));
        collector.record(sample("upload", Outcome::Failed, 20.0));

        let upload = &collector.summarize(1_000.0)[0];
        assert_eq!((upload.ok, upload.throttled, upload.failed), (1, 1, 1));
        assert!((upload.error_rate() - 1.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn throttling_is_not_counted_as_an_error() {
        let mut collector = Collector::default();
        for _ in 0..4 {
            collector.record(sample("upload", Outcome::Throttled, 1.0));
        }
        let upload = &collector.summarize(1_000.0)[0];
        assert_eq!(upload.error_rate(), 0.0);
        assert_eq!(upload.throttled, 4);
    }

    #[test]
    fn each_operation_summarizes_separately_alongside_an_all_total() {
        let mut collector = Collector::default();
        collector.record(sample("upload", Outcome::Ok, 10.0));
        collector.record(sample("register", Outcome::Ok, 30.0));

        let summaries = collector.summarize(1_000.0);
        let ops: Vec<&str> = summaries.iter().map(|s| s.op).collect();
        assert_eq!(ops, vec!["upload", "register", "all"]);
        assert_eq!(summaries[2].count, 2);
        assert_eq!(summaries[2].p50_ms, 10.0);
    }

    #[test]
    fn throughput_divides_by_the_wall_clock() {
        let mut collector = Collector::default();
        for _ in 0..10 {
            collector.record(sample("upload", Outcome::Ok, 1.0).with_bytes(1_024));
        }
        let upload = &collector.summarize(2_000.0)[0];
        assert_eq!(upload.ops_per_sec, 5.0);
        assert_eq!(upload.bytes_per_sec, 5_120.0);
    }

    #[test]
    fn a_zero_length_run_does_not_divide_by_zero() {
        let mut collector = Collector::default();
        collector.record(sample("upload", Outcome::Ok, 1.0));
        let upload = &collector.summarize(0.0)[0];
        assert!(upload.ops_per_sec.is_finite());
    }

    #[test]
    fn absorbed_collectors_merge_their_samples() {
        let mut left = Collector::default();
        left.record(sample("upload", Outcome::Ok, 1.0));
        let mut right = Collector::default();
        right.record(sample("upload", Outcome::Ok, 3.0));
        left.absorb(right);
        assert_eq!(left.summarize(1_000.0)[0].count, 2);
    }

    #[test]
    fn the_first_failure_detail_surfaces_on_the_collector_and_on_its_operation() {
        let mut collector = Collector::default();
        collector.record(sample("login", Outcome::Ok, 1.0));
        collector.record(sample("login", Outcome::Failed, 1.0).with_detail("connection refused"));
        collector.record(sample("login", Outcome::Failed, 1.0).with_detail("later, ignored"));

        assert_eq!(collector.first_failure(), Some("connection refused"));
        assert_eq!(
            collector.summarize(1_000.0)[0].first_failure.as_deref(),
            Some("connection refused")
        );
    }
}
