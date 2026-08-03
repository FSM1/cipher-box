//! `cipherbox-load` — the dispatch-tier load harness entry point.

use std::process::ExitCode;

use cipherbox_load::plan::{RunPlan, Scenario, build_plan, parse_args, process_env};
use cipherbox_load::report::{print_summary, report_file_name, to_json};
use cipherbox_load::runner;
use cipherbox_load::thresholds::{evaluate, thresholds_for};

const USAGE: &str = "\
usage: cipherbox-load --scenario <name> --target <local|staging> [options]

options:
  --clients <n>          concurrent accounts               (default 5)
  --ops-per-client <n>   iterations per account            (default 20)
  --block-bytes <n>      upload block size, max 2 MiB      (default 65536)
  --batch-size <n>       registry batch size, max 1000     (default 25)
  --pace-ms <n>          delay between an account's ops    (default 0 local, 1200 staging)
  --ramp-ms <n>          per-client start stagger          (default 0)
  --report-dir <path>    where the JSON report is written  (default load-reports)

environment:
  LOAD_TEST_API_URL        required for staging; loopback-only for local
  LOAD_TEST_SECRET         required; must equal the API's TEST_LOGIN_SECRET
  LOAD_TEST_GATEWAY_URL    read accelerator, for the gateway-read scenario
  LOAD_TEST_GATEWAY_TOKEN  bearer token for a gateway behind forward_auth";

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(message) => {
            eprintln!("cipherbox-load: {message}\n\n{USAGE}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("{USAGE}\n\nscenarios: {}", Scenario::names());
        return Ok(ExitCode::SUCCESS);
    }
    let flags = parse_args(&args).map_err(|error| error.to_string())?;
    let plan = build_plan(&flags, process_env).map_err(|error| error.to_string())?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("build the tokio runtime: {error}"))?;
    let local = tokio::task::LocalSet::new();
    let (collector, wall_ms) = local.block_on(&runtime, runner::run(&plan))?;

    let summaries = collector.summarize(wall_ms);
    let thresholds = thresholds_for(plan.scenario, plan.target);
    let breaches = evaluate(thresholds, &summaries);

    print_summary(&plan, &summaries, wall_ms);
    write_report(
        &plan,
        &to_json(&plan, &summaries, wall_ms, thresholds, &breaches),
    )?;

    if breaches.is_empty() {
        return Ok(ExitCode::SUCCESS);
    }
    for breach in &breaches {
        eprintln!("threshold breach: {breach}");
    }
    Ok(ExitCode::FAILURE)
}

fn write_report(plan: &RunPlan, json: &str) -> Result<(), String> {
    std::fs::create_dir_all(&plan.report_dir)
        .map_err(|error| format!("create {}: {error}", plan.report_dir))?;
    let path = std::path::Path::new(&plan.report_dir).join(report_file_name(plan));
    std::fs::write(&path, json).map_err(|error| format!("write {}: {error}", path.display()))?;
    println!("report: {}", path.display());
    Ok(())
}
