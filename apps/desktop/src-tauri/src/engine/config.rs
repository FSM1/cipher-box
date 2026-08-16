//! What this build points the engine at.
//!
//! The values are the bundle's own build-time variables: `scripts/tauri.mjs`
//! resolves them once and hands the same set to the frontend build, the CSP,
//! and this crate's compile, so the identity exchange the webview posts to and
//! the API the engine logs in against are the same deployment by construction.
//! Nothing is defaulted here — a missing `VITE_API_URL` is refused by name, so
//! a build made outside that script cannot silently address localhost.

use cipherbox_engine::facade::ApiBaseUrl;
use cipherbox_engine::{GatewayConfig, StoragePolicy, SyncTimingProfile};

/// The build-time variables the engine host reads.
pub struct BuildEnv {
    /// The API origin, shared with the identity exchange (`src/config.ts`).
    pub api_base_url: Option<&'static str>,
    /// Comma-separated `/routing/v1` base URLs.
    pub routing_endpoints: Option<&'static str>,
    /// The member read accelerator, if this deployment has one.
    pub read_accelerator_url: Option<&'static str>,
    /// Comma-separated trustless-gateway fallbacks.
    pub public_gateways: Option<&'static str>,
    /// Which deployment this build is; only `ci` changes engine behavior.
    pub environment: Option<&'static str>,
}

impl BuildEnv {
    /// The variables this binary was compiled with. `build.rs` marks each one
    /// as a rebuild trigger, so a changed value is a recompile rather than a
    /// stale constant.
    pub const fn compiled() -> Self {
        Self {
            api_base_url: option_env!("VITE_API_URL"),
            routing_endpoints: option_env!("VITE_ROUTING_ENDPOINTS"),
            read_accelerator_url: option_env!("VITE_READ_ACCELERATOR_URL"),
            public_gateways: option_env!("VITE_PUBLIC_GATEWAYS"),
            environment: option_env!("VITE_ENVIRONMENT"),
        }
    }
}

/// The engine construction arguments this build resolves to.
#[derive(Debug)]
pub struct EngineConfig {
    /// The API the engine authenticates and publishes against, non-blank.
    pub api_base_url: String,
    /// `/routing/v1` endpoints the record transport fans out over.
    pub record_endpoints: Vec<String>,
    /// Content read sources.
    pub gateway: GatewayConfig,
    /// Sync cadences.
    pub profile: SyncTimingProfile,
    /// The staging/cache split this device runs under.
    pub storage_policy: StoragePolicy,
}

impl EngineConfig {
    /// Resolves the configuration this binary was compiled with.
    pub fn compiled() -> Result<Self, String> {
        Self::parse(&BuildEnv::compiled())
    }

    /// Reads `env` into the engine's construction arguments, refusing a build
    /// that names no API and one that names no routing endpoint — the second
    /// mirrors the record transport's own empty-set rejection, which is a
    /// panic rather than an error once construction reaches it.
    pub fn parse(env: &BuildEnv) -> Result<Self, String> {
        let api_base_url = configured(env.api_base_url)
            .ok_or("this build names no API: set VITE_API_URL, or build through `pnpm tauri`")?;
        // The engine's own edge check, run here so the refusal names the
        // variable rather than surfacing as a failed login.
        ApiBaseUrl::parse(api_base_url).map_err(|error| error.to_string())?;

        let record_endpoints = list(env.routing_endpoints);
        if record_endpoints.is_empty() {
            return Err(
                "VITE_ROUTING_ENDPOINTS must list at least one routing endpoint".to_owned(),
            );
        }

        let ci = configured(env.environment) == Some("ci");
        Ok(Self {
            api_base_url: api_base_url.to_owned(),
            record_endpoints,
            // No default: unset reads nothing rather than reaching for an
            // endpoint nobody chose, and content reads fail closed as
            // unavailable until one is configured.
            gateway: GatewayConfig {
                accelerator: configured(env.read_accelerator_url).map(str::to_owned),
                public_fallbacks: list(env.public_gateways),
            },
            profile: if ci {
                SyncTimingProfile::CI
            } else {
                SyncTimingProfile::PRODUCTION
            },
            // This shell opens no write handle, so it has measured no headroom
            // to split; the volume measurement arrives with the mount
            // (blueprint/desktop.md). Unmeasured is the honest state — a
            // refusal then says "unknown", never "full".
            storage_policy: if ci {
                StoragePolicy::CI
            } else {
                StoragePolicy::UNMEASURED
            },
        })
    }
}

/// Absent, empty and whitespace-only are one state: a repo variable set to a
/// stray space is unset, not configured (`src/config.ts`).
fn configured(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

/// Reads a comma-separated variable as a trimmed, blank-free list.
fn list(value: Option<&'static str>) -> Vec<String> {
    value
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> BuildEnv {
        BuildEnv {
            api_base_url: Some("https://api.example.test"),
            routing_endpoints: Some("https://someguy.example.test"),
            read_accelerator_url: None,
            public_gateways: None,
            environment: None,
        }
    }

    #[test]
    fn a_build_that_names_no_api_is_refused_by_variable_name() {
        for api_base_url in [None, Some(""), Some("   ")] {
            let error = EngineConfig::parse(&BuildEnv {
                api_base_url,
                ..env()
            })
            .expect_err("no API is a configuration failure");
            assert!(error.contains("VITE_API_URL"), "{error}");
        }
    }

    #[test]
    fn a_build_with_no_routing_endpoint_is_refused_before_the_transport_panics() {
        for routing_endpoints in [None, Some(""), Some(" , ")] {
            let error = EngineConfig::parse(&BuildEnv {
                routing_endpoints,
                ..env()
            })
            .expect_err("an empty endpoint set is a configuration failure");
            assert!(error.contains("VITE_ROUTING_ENDPOINTS"), "{error}");
        }
    }

    #[test]
    fn lists_are_trimmed_and_blank_free() {
        let config = EngineConfig::parse(&BuildEnv {
            routing_endpoints: Some(" https://a.example.test , https://b.example.test "),
            public_gateways: Some(" https://gw.example.test ,, "),
            ..env()
        })
        .expect("a configured build parses");

        assert_eq!(
            config.record_endpoints,
            ["https://a.example.test", "https://b.example.test"],
        );
        assert_eq!(config.gateway.public_fallbacks, ["https://gw.example.test"]);
    }

    #[test]
    fn an_unconfigured_gateway_stays_dormant() {
        let config = EngineConfig::parse(&BuildEnv {
            read_accelerator_url: Some("  "),
            public_gateways: Some(" , "),
            ..env()
        })
        .expect("a configured build parses");

        assert_eq!(config.gateway.accelerator, None);
        assert!(config.gateway.public_fallbacks.is_empty());
    }

    /// Only `ci` compresses the cadences; a typo must not silently select them.
    #[test]
    fn the_ci_environment_is_the_only_one_that_moves_off_production_timings() {
        for environment in [None, Some("local"), Some("staging"), Some("production")] {
            let config = EngineConfig::parse(&BuildEnv {
                environment,
                ..env()
            })
            .expect("a configured build parses");
            assert_eq!(config.profile, SyncTimingProfile::PRODUCTION);
            assert_eq!(config.storage_policy, StoragePolicy::UNMEASURED);
        }

        let ci = EngineConfig::parse(&BuildEnv {
            environment: Some("ci"),
            ..env()
        })
        .expect("a configured build parses");
        assert_eq!(ci.profile, SyncTimingProfile::CI);
        assert_eq!(ci.storage_policy, StoragePolicy::CI);
    }
}
