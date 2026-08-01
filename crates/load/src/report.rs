//! Human-readable summary and the JSON artifact a dispatched run uploads.

use serde_json::{Value, json};

use crate::metrics::OpSummary;
use crate::plan::RunPlan;
use crate::thresholds::{Breach, Thresholds};

pub fn print_summary(plan: &RunPlan, summaries: &[OpSummary], wall_ms: f64) {
    println!(
        "\n{} on {} — {} clients, {:.1}s",
        plan.scenario.as_str(),
        plan.target.as_str(),
        plan.clients,
        wall_ms / 1_000.0
    );
    println!(
        "{:<20} {:>7} {:>5} {:>5} {:>9} {:>9} {:>9} {:>9}",
        "operation", "count", "429", "err", "p50 ms", "p95 ms", "p99 ms", "ops/s"
    );
    for row in summaries {
        println!(
            "{:<20} {:>7} {:>5} {:>5} {:>9.1} {:>9.1} {:>9.1} {:>9.2}",
            row.op,
            row.count,
            row.throttled,
            row.failed,
            row.p50_ms,
            row.p95_ms,
            row.p99_ms,
            row.ops_per_sec
        );
    }
    if let Some(total) = summaries.iter().find(|row| row.op == "all")
        && total.bytes > 0
    {
        println!(
            "throughput: {:.2} MiB/s over {:.2} MiB",
            total.bytes_per_sec / (1024.0 * 1024.0),
            total.bytes as f64 / (1024.0 * 1024.0)
        );
    }
}

pub fn to_json(
    plan: &RunPlan,
    summaries: &[OpSummary],
    wall_ms: f64,
    thresholds: Thresholds,
    breaches: &[Breach],
) -> String {
    let operations: Vec<Value> = summaries
        .iter()
        .map(|row| {
            json!({
                "op": row.op,
                "count": row.count,
                "ok": row.ok,
                "throttled": row.throttled,
                "failed": row.failed,
                "p50Ms": round(row.p50_ms),
                "p95Ms": round(row.p95_ms),
                "p99Ms": round(row.p99_ms),
                "maxMs": round(row.max_ms),
                "opsPerSec": round(row.ops_per_sec),
                "bytes": row.bytes,
                "bytesPerSec": round(row.bytes_per_sec),
            })
        })
        .collect();

    let report = json!({
        "scenario": plan.scenario.as_str(),
        "target": plan.target.as_str(),
        "clients": plan.clients,
        "opsPerClient": plan.ops_per_client,
        "blockBytes": plan.block_bytes,
        "batchSize": plan.batch_size,
        "paceMs": plan.pace_ms,
        "rampMs": plan.ramp_ms,
        "wallMs": round(wall_ms),
        "thresholds": { "p95Ms": thresholds.p95_ms, "maxErrorRate": thresholds.max_error_rate },
        "breaches": breaches.iter().map(|breach| breach.0.clone()).collect::<Vec<_>>(),
        "operations": operations,
    });
    serde_json::to_string_pretty(&report).expect("serialize report")
}

fn round(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

/// The artifact name a dispatched run uploads: one file per scenario+target.
pub fn report_file_name(plan: &RunPlan) -> String {
    format!(
        "metrics-{}-{}.json",
        plan.scenario.as_str(),
        plan.target.as_str()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::{Collector, Outcome, Sample};
    use crate::plan::{Scenario, Target};
    use crate::thresholds::thresholds_for;

    fn plan() -> RunPlan {
        RunPlan {
            scenario: Scenario::ContentIngest,
            target: Target::Local,
            api_url: "http://localhost:3000".into(),
            gateway_url: None,
            gateway_token: None,
            test_login_secret: "secret".into(),
            clients: 2,
            ops_per_client: 3,
            block_bytes: 1_024,
            batch_size: 25,
            pace_ms: 0,
            ramp_ms: 0,
            report_dir: "load-reports".into(),
        }
    }

    #[test]
    fn the_report_carries_the_shape_of_the_run_and_its_breaches() {
        let mut collector = Collector::default();
        collector.record(Sample::new("content-upload", Outcome::Ok, 12.0).with_bytes(1_024));
        collector.record(Sample::new("content-upload", Outcome::Throttled, 3.0));
        let summaries = collector.summarize(1_000.0);
        let bands = thresholds_for(Scenario::ContentIngest, Target::Local);
        let breaches = vec![Breach("p95 9000ms exceeds the 2000ms band".into())];

        let rendered = to_json(&plan(), &summaries, 1_000.0, bands, &breaches);
        let value: Value = serde_json::from_str(&rendered).expect("valid json");
        assert_eq!(value["scenario"], "content-ingest");
        assert_eq!(value["target"], "local");
        assert_eq!(value["clients"], 2);
        assert_eq!(value["operations"][0]["op"], "content-upload");
        assert_eq!(value["operations"][0]["throttled"], 1);
        assert_eq!(value["operations"][1]["op"], "all");
        assert_eq!(value["breaches"].as_array().expect("array").len(), 1);
        assert_eq!(value["thresholds"]["p95Ms"], 2_000.0);
    }

    #[test]
    fn a_report_file_is_named_for_its_scenario_and_target() {
        assert_eq!(
            report_file_name(&plan()),
            "metrics-content-ingest-local.json"
        );
    }
}
