//! CipherBox wasm: wasm-bindgen bindings exposing the engine to the web
//! client (`packages/client`), hosted in a worker.
//!
//! Normative design: blueprint/web-client.md

/// Placeholder identity item; the real bindings land in later PRs.
pub const CRATE: &str = "cipherbox-wasm";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name() {
        assert_eq!(super::CRATE, "cipherbox-wasm");
    }

    #[test]
    fn depends_on_engine() {
        assert_eq!(cipherbox_engine::CRATE, "cipherbox-engine");
    }
}
