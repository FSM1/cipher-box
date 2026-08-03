//! The run plan: what the harness is allowed to do, and where it is allowed to
//! point.
//!
//! A load generator aimed at the wrong host is an outage, so target resolution
//! is an allowlist, not a URL passthrough: `local` only ever reaches loopback,
//! `staging` only ever reaches a non-loopback https URL supplied out of band by
//! the workflow's gated `staging` environment, and there is no third target.

use std::collections::BTreeMap;
use std::net::IpAddr;

/// A load scenario. Each maps to one v2 API surface (blueprint/api.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    /// Hosted content ingress throughput: caller-addressed block uploads.
    ContentIngest,
    /// Read-accelerator throughput: fetching blocks back off the gateway.
    GatewayRead,
    /// Registry cadence under a name wave: bulk register then retire.
    NameWave,
    /// Ingest, registry, quota and mailbox interleaved on one account.
    Mixed,
    /// A BYO account's advisory pin rows: the registry path that never gates.
    ByoAdvisory,
}

impl Scenario {
    pub const ALL: [Scenario; 5] = [
        Scenario::ContentIngest,
        Scenario::GatewayRead,
        Scenario::NameWave,
        Scenario::Mixed,
        Scenario::ByoAdvisory,
    ];

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.as_str() == value)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Scenario::ContentIngest => "content-ingest",
            Scenario::GatewayRead => "gateway-read",
            Scenario::NameWave => "name-wave",
            Scenario::Mixed => "mixed",
            Scenario::ByoAdvisory => "byo-advisory",
        }
    }

    /// Whether the scenario reads blocks back off the read accelerator.
    fn needs_gateway(self) -> bool {
        self == Scenario::GatewayRead
    }

    /// The wire names, for usage text and error messages.
    pub fn names() -> String {
        Self::ALL
            .iter()
            .map(|scenario| scenario.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Where the load lands. There is deliberately no production target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Local,
    Staging,
}

impl Target {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "local" => Some(Target::Local),
            "staging" => Some(Target::Staging),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Target::Local => "local",
            Target::Staging => "staging",
        }
    }

    /// Concurrent-account ceiling. Staging is one 2-vCPU VPS whose cores Kubo
    /// and someguy already share (blueprint/deploy.md), so its ceiling is the
    /// hardware, not the harness.
    pub fn max_clients(self) -> u64 {
        match self {
            Target::Local => 50,
            Target::Staging => 8,
        }
    }

    pub fn max_ops_per_client(self) -> u64 {
        match self {
            Target::Local => 500,
            Target::Staging => 50,
        }
    }

    /// Default per-account delay between operations. Staging paces just under
    /// the API's own 60-per-minute content bucket so a run measures the system
    /// rather than the throttler, and never crowds someguy off the box.
    pub fn default_pace_ms(self) -> u64 {
        match self {
            Target::Local => 0,
            Target::Staging => 1_200,
        }
    }
}

/// The API's block ceiling: one request, one block (blueprint/api.md).
pub const MAX_BLOCK_BYTES: u32 = 2 * 1024 * 1024;
/// The registry's batch cap, published as `maxItems` (blueprint/api.md).
pub const MAX_BATCH: u32 = 1000;

const DEFAULT_LOCAL_API_URL: &str = "http://localhost:3000";
const DEFAULT_LOCAL_GATEWAY_URL: &str = "http://localhost:8080";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanError(pub String);

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PlanError {}

fn bad(message: impl Into<String>) -> PlanError {
    PlanError(message.into())
}

/// A fully resolved, bounds-checked run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunPlan {
    pub scenario: Scenario,
    pub target: Target,
    pub api_url: String,
    pub gateway_url: Option<String>,
    pub gateway_token: Option<String>,
    pub test_login_secret: String,
    pub clients: u32,
    pub ops_per_client: u32,
    pub block_bytes: u32,
    pub batch_size: u32,
    pub pace_ms: u64,
    pub ramp_ms: u64,
    pub report_dir: String,
}

/// Parse `--key value` pairs. Repeats and unknown keys are rejected rather than
/// silently taking the last value: a mis-typed flag on a load run is a run with
/// the wrong shape, and a wrong shape is worse than no run.
pub fn parse_args<I, S>(args: I) -> Result<BTreeMap<String, String>, PlanError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let mut iter = args.into_iter();
    while let Some(raw) = iter.next() {
        let key = raw.as_ref();
        let Some(name) = key.strip_prefix("--") else {
            return Err(bad(format!("expected a --flag, got `{key}`")));
        };
        let Some(value) = iter.next() else {
            return Err(bad(format!("`--{name}` expects a value")));
        };
        if out
            .insert(name.to_owned(), value.as_ref().to_owned())
            .is_some()
        {
            return Err(bad(format!("`--{name}` given more than once")));
        }
    }
    Ok(out)
}

/// The environment lookup, injected so the guard is testable without touching
/// the process environment.
pub fn process_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|value| !value.is_empty())
}

/// The host portion of an `http(s)://host[:port]/...` URL.
fn host_of(url: &str) -> Option<&str> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?;
    if let Some(bracketed) = authority.strip_prefix('[') {
        return bracketed.split(']').next().filter(|h| !h.is_empty());
    }
    authority.split(':').next().filter(|h| !h.is_empty())
}

fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

/// Every URL the harness may reach passes the target's host policy — the API
/// and the read accelerator alike, since a bearer token rides to the latter.
fn guard_url(target: Target, key: &str, url: &str) -> Result<(), PlanError> {
    let host = host_of(url).ok_or_else(|| bad(format!("{key} `{url}` is not an http(s) URL")))?;
    match target {
        Target::Local if !is_loopback(host) => Err(bad(format!(
            "target `local` refuses the non-loopback host `{host}` in {key}; dispatch with --target staging to reach a deployed stack"
        ))),
        Target::Staging if is_loopback(host) => Err(bad(format!(
            "target `staging` refuses the loopback host `{host}` in {key}; use --target local"
        ))),
        Target::Staging if !url.starts_with("https://") => {
            Err(bad(format!("target `staging` requires an https {key}")))
        }
        _ => Ok(()),
    }
}

/// Both readers concatenate base and path (`crates/engine/src/api/client.rs`
/// `url`, and the gateway URL in `crates/load/src/scenarios.rs`), so a trailing
/// slash on an operator-supplied base would request `//content/upload`.
fn normalize_base(url: String) -> String {
    url.trim_end_matches('/').to_owned()
}

fn resolve_api_url(
    target: Target,
    env: &impl Fn(&str) -> Option<String>,
) -> Result<String, PlanError> {
    let url = match (env("LOAD_TEST_API_URL"), target) {
        (Some(url), _) => url,
        (None, Target::Local) => DEFAULT_LOCAL_API_URL.to_owned(),
        (None, Target::Staging) => {
            return Err(bad(
                "target `staging` requires LOAD_TEST_API_URL; it is supplied by the workflow's gated staging environment",
            ));
        }
    };
    guard_url(target, "LOAD_TEST_API_URL", &url)?;
    Ok(normalize_base(url))
}

fn resolve_gateway_url(
    scenario: Scenario,
    target: Target,
    env: &impl Fn(&str) -> Option<String>,
) -> Result<Option<String>, PlanError> {
    if !scenario.needs_gateway() {
        return Ok(None);
    }
    let url = match (env("LOAD_TEST_GATEWAY_URL"), target) {
        (Some(url), _) => url,
        (None, Target::Local) => DEFAULT_LOCAL_GATEWAY_URL.to_owned(),
        (None, Target::Staging) => {
            return Err(bad(
                "scenario `gateway-read` requires LOAD_TEST_GATEWAY_URL on a deployed target",
            ));
        }
    };
    guard_url(target, "LOAD_TEST_GATEWAY_URL", &url)?;
    Ok(Some(normalize_base(url)))
}

/// Every dimension of a run is bounded, so no flag combination can turn a
/// dispatched run into an unbounded one.
fn bounded(
    flags: &mut BTreeMap<String, String>,
    key: &str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<u64, PlanError> {
    let Some(raw) = flags.remove(key) else {
        return Ok(default);
    };
    let value: u64 = raw
        .parse()
        .map_err(|_| bad(format!("`--{key}` expects a whole number, got `{raw}`")))?;
    if value < min || value > max {
        return Err(bad(format!(
            "`--{key}` must be between {min} and {max}, got {value}"
        )));
    }
    Ok(value)
}

/// A ceiling on the two delay flags: a run whose every other dimension is
/// bounded should not be able to stall for a day between operations.
const MAX_DELAY_MS: u64 = 60_000;

/// Resolve command-line flags and the environment into a bounds-checked plan.
/// Flags are consumed as they are read, so anything left over was misspelled.
pub fn build_plan(
    flags: &BTreeMap<String, String>,
    env: impl Fn(&str) -> Option<String>,
) -> Result<RunPlan, PlanError> {
    let mut flags = flags.clone();

    let scenario_name = flags
        .remove("scenario")
        .ok_or_else(|| bad("`--scenario` is required"))?;
    let scenario = Scenario::parse(&scenario_name).ok_or_else(|| {
        bad(format!(
            "unknown scenario `{scenario_name}`; expected one of {}",
            Scenario::names()
        ))
    })?;
    let target_name = flags
        .remove("target")
        .ok_or_else(|| bad("`--target` is required"))?;
    let target = Target::parse(&target_name).ok_or_else(|| {
        bad(format!(
            "unknown target `{target_name}`; expected local or staging"
        ))
    })?;

    let plan = RunPlan {
        scenario,
        target,
        api_url: resolve_api_url(target, &env)?,
        gateway_url: resolve_gateway_url(scenario, target, &env)?,
        gateway_token: env("LOAD_TEST_GATEWAY_TOKEN"),
        test_login_secret: env("LOAD_TEST_SECRET").ok_or_else(|| {
            bad("LOAD_TEST_SECRET is required; it must equal the API's TEST_LOGIN_SECRET")
        })?,
        clients: bounded(&mut flags, "clients", 5, 1, target.max_clients())? as u32,
        ops_per_client: bounded(
            &mut flags,
            "ops-per-client",
            20,
            1,
            target.max_ops_per_client(),
        )? as u32,
        block_bytes: bounded(
            &mut flags,
            "block-bytes",
            64 * 1024,
            1,
            u64::from(MAX_BLOCK_BYTES),
        )? as u32,
        batch_size: bounded(&mut flags, "batch-size", 25, 1, u64::from(MAX_BATCH))? as u32,
        pace_ms: bounded(
            &mut flags,
            "pace-ms",
            target.default_pace_ms(),
            0,
            MAX_DELAY_MS,
        )?,
        ramp_ms: bounded(&mut flags, "ramp-ms", 0, 0, MAX_DELAY_MS)?,
        report_dir: flags
            .remove("report-dir")
            .unwrap_or_else(|| "load-reports".to_owned()),
    };

    if let Some(unknown) = flags.keys().next() {
        return Err(bad(format!("unknown flag `--{unknown}`")));
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn flags(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        env(pairs)
    }

    /// The env closure the guard reads, backed by a fixture map.
    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let map = env(pairs);
        move |key: &str| map.get(key).cloned().filter(|value| !value.is_empty())
    }

    fn local_env() -> impl Fn(&str) -> Option<String> {
        lookup(&[("LOAD_TEST_SECRET", "load-secret")])
    }

    #[test]
    fn every_scenario_round_trips_through_its_wire_name() {
        for scenario in Scenario::ALL {
            assert_eq!(Scenario::parse(scenario.as_str()), Some(scenario));
        }
    }

    #[test]
    fn an_unknown_scenario_is_refused() {
        assert!(Scenario::parse("upload-throughput").is_none());
    }

    #[test]
    fn there_is_no_production_target() {
        assert!(Target::parse("production").is_none());
        assert!(Target::parse("prod").is_none());
    }

    #[test]
    fn args_parse_into_flag_pairs() {
        let parsed = parse_args(["--scenario", "mixed", "--clients", "3"]).expect("parse");
        assert_eq!(parsed.get("scenario").map(String::as_str), Some("mixed"));
        assert_eq!(parsed.get("clients").map(String::as_str), Some("3"));
    }

    #[test]
    fn a_repeated_flag_is_refused() {
        let error = parse_args(["--clients", "3", "--clients", "9"]).expect_err("refused");
        assert!(error.0.contains("more than once"), "{error}");
    }

    #[test]
    fn a_dangling_flag_is_refused() {
        assert!(parse_args(["--clients"]).is_err());
        assert!(parse_args(["clients", "3"]).is_err());
    }

    #[test]
    fn an_unknown_flag_is_refused() {
        let error = build_plan(
            &flags(&[("scenario", "mixed"), ("target", "local"), ("vus", "9")]),
            local_env(),
        )
        .expect_err("refused");
        assert!(error.0.contains("unknown flag `--vus`"), "{error}");
    }

    #[test]
    fn local_defaults_to_loopback() {
        let plan = build_plan(
            &flags(&[("scenario", "mixed"), ("target", "local")]),
            local_env(),
        )
        .expect("plan");
        assert_eq!(plan.api_url, "http://localhost:3000");
        assert_eq!(plan.pace_ms, 0);
    }

    #[test]
    fn local_refuses_a_non_loopback_url() {
        let error = build_plan(
            &flags(&[("scenario", "mixed"), ("target", "local")]),
            lookup(&[
                ("LOAD_TEST_SECRET", "s"),
                ("LOAD_TEST_API_URL", "https://api.staging.example.com"),
            ]),
        )
        .expect_err("refused");
        assert!(error.0.contains("non-loopback"), "{error}");
    }

    #[test]
    fn staging_requires_an_https_url_from_the_environment() {
        let missing = build_plan(
            &flags(&[("scenario", "mixed"), ("target", "staging")]),
            local_env(),
        )
        .expect_err("refused");
        assert!(missing.0.contains("LOAD_TEST_API_URL"), "{missing}");

        let plaintext = build_plan(
            &flags(&[("scenario", "mixed"), ("target", "staging")]),
            lookup(&[
                ("LOAD_TEST_SECRET", "s"),
                ("LOAD_TEST_API_URL", "http://api.staging.example.com"),
            ]),
        )
        .expect_err("refused");
        assert!(plaintext.0.contains("https"), "{plaintext}");
    }

    #[test]
    fn staging_refuses_a_loopback_url() {
        let error = build_plan(
            &flags(&[("scenario", "mixed"), ("target", "staging")]),
            lookup(&[
                ("LOAD_TEST_SECRET", "s"),
                ("LOAD_TEST_API_URL", "https://127.0.0.1:3000"),
            ]),
        )
        .expect_err("refused");
        assert!(error.0.contains("loopback"), "{error}");
    }

    #[test]
    fn staging_caps_clients_below_the_two_vcpu_ceiling() {
        let staging_env = || {
            lookup(&[
                ("LOAD_TEST_SECRET", "s"),
                ("LOAD_TEST_API_URL", "https://api.staging.example.com"),
            ])
        };
        let error = build_plan(
            &flags(&[
                ("scenario", "mixed"),
                ("target", "staging"),
                ("clients", "40"),
            ]),
            staging_env(),
        )
        .expect_err("refused");
        assert!(error.0.contains("between 1 and 8"), "{error}");

        let plan = build_plan(
            &flags(&[
                ("scenario", "mixed"),
                ("target", "staging"),
                ("clients", "8"),
            ]),
            staging_env(),
        )
        .expect("plan");
        assert_eq!(plan.clients, 8);
        assert_eq!(
            plan.pace_ms, 1_200,
            "staging paces under the content bucket"
        );
    }

    #[test]
    fn a_block_over_the_api_ceiling_is_refused() {
        let error = build_plan(
            &flags(&[
                ("scenario", "content-ingest"),
                ("target", "local"),
                ("block-bytes", "4194304"),
            ]),
            local_env(),
        )
        .expect_err("refused");
        assert!(error.0.contains("between 1 and 2097152"), "{error}");
    }

    #[test]
    fn a_batch_over_the_registry_cap_is_refused() {
        let error = build_plan(
            &flags(&[
                ("scenario", "name-wave"),
                ("target", "local"),
                ("batch-size", "1001"),
            ]),
            local_env(),
        )
        .expect_err("refused");
        assert!(error.0.contains("between 1 and 1000"), "{error}");
    }

    #[test]
    fn a_zero_or_malformed_count_is_refused() {
        for value in ["0", "-1", "many"] {
            assert!(
                build_plan(
                    &flags(&[
                        ("scenario", "mixed"),
                        ("target", "local"),
                        ("clients", value)
                    ]),
                    local_env(),
                )
                .is_err(),
                "`--clients {value}` should be refused"
            );
        }
    }

    #[test]
    fn a_missing_login_secret_is_refused() {
        let error = build_plan(
            &flags(&[("scenario", "mixed"), ("target", "local")]),
            lookup(&[]),
        )
        .expect_err("refused");
        assert!(error.0.contains("LOAD_TEST_SECRET"), "{error}");
    }

    #[test]
    fn the_gateway_url_is_resolved_only_for_the_read_scenario() {
        let read = build_plan(
            &flags(&[("scenario", "gateway-read"), ("target", "local")]),
            local_env(),
        )
        .expect("plan");
        assert_eq!(read.gateway_url.as_deref(), Some("http://localhost:8080"));

        let ingest = build_plan(
            &flags(&[("scenario", "content-ingest"), ("target", "local")]),
            local_env(),
        )
        .expect("plan");
        assert_eq!(ingest.gateway_url, None);
    }

    #[test]
    fn the_gateway_url_passes_the_same_host_policy_as_the_api_url() {
        let error = build_plan(
            &flags(&[("scenario", "gateway-read"), ("target", "local")]),
            lookup(&[
                ("LOAD_TEST_SECRET", "s"),
                ("LOAD_TEST_GATEWAY_URL", "https://gateway.example.com"),
            ]),
        )
        .expect_err("refused");
        assert!(error.0.contains("LOAD_TEST_GATEWAY_URL"), "{error}");
        assert!(error.0.contains("non-loopback"), "{error}");

        let plaintext = build_plan(
            &flags(&[("scenario", "gateway-read"), ("target", "staging")]),
            lookup(&[
                ("LOAD_TEST_SECRET", "s"),
                ("LOAD_TEST_API_URL", "https://api.staging.example.com"),
                (
                    "LOAD_TEST_GATEWAY_URL",
                    "http://gateway.staging.example.com",
                ),
            ]),
        )
        .expect_err("refused");
        assert!(
            plaintext.0.contains("https LOAD_TEST_GATEWAY_URL"),
            "{plaintext}"
        );
    }

    #[test]
    fn loopback_recognition_spans_the_whole_127_block_and_nothing_that_merely_looks_like_it() {
        assert!(is_loopback("localhost"));
        assert!(is_loopback("LocalHost"));
        assert!(is_loopback("127.0.0.1"));
        assert!(is_loopback("127.99.4.7"));
        assert!(is_loopback("::1"));
        assert!(!is_loopback("127.evil.example.com"));
        assert!(!is_loopback("1270.0.0.1"));
        assert!(!is_loopback("localhost.evil.example.com"));
    }

    #[test]
    fn a_deployed_gateway_read_needs_an_explicit_gateway_url() {
        let error = build_plan(
            &flags(&[("scenario", "gateway-read"), ("target", "staging")]),
            lookup(&[
                ("LOAD_TEST_SECRET", "s"),
                ("LOAD_TEST_API_URL", "https://api.staging.example.com"),
            ]),
        )
        .expect_err("refused");
        assert!(error.0.contains("LOAD_TEST_GATEWAY_URL"), "{error}");
    }

    #[test]
    fn a_trailing_slash_never_survives_into_a_request_path() {
        let plan = build_plan(
            &flags(&[("scenario", "gateway-read"), ("target", "staging")]),
            lookup(&[
                ("LOAD_TEST_SECRET", "s"),
                ("LOAD_TEST_API_URL", "https://api.staging.example.com//"),
                (
                    "LOAD_TEST_GATEWAY_URL",
                    "https://gateway.staging.example.com/",
                ),
            ]),
        )
        .expect("plan");
        assert_eq!(plan.api_url, "https://api.staging.example.com");
        assert_eq!(
            plan.gateway_url.as_deref(),
            Some("https://gateway.staging.example.com")
        );
    }

    #[test]
    fn hosts_are_extracted_from_every_url_shape() {
        assert_eq!(host_of("http://localhost:3000/x"), Some("localhost"));
        assert_eq!(host_of("https://api.example.com"), Some("api.example.com"));
        assert_eq!(host_of("http://[::1]:8080/y"), Some("::1"));
        assert_eq!(
            host_of("https://user@evil.example.com"),
            Some("evil.example.com")
        );
        assert_eq!(host_of("ftp://example.com"), None);
        assert_eq!(host_of("http://"), None);
    }

    #[test]
    fn a_credential_prefixed_url_cannot_smuggle_a_loopback_target() {
        let error = build_plan(
            &flags(&[("scenario", "mixed"), ("target", "local")]),
            lookup(&[
                ("LOAD_TEST_SECRET", "s"),
                ("LOAD_TEST_API_URL", "http://localhost@api.example.com/"),
            ]),
        )
        .expect_err("refused");
        assert!(error.0.contains("non-loopback"), "{error}");
    }
}
