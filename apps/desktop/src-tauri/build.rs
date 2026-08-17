fn main() {
    // The engine's configuration is compiled in from these variables
    // (`src/engine/config.rs`), so a changed value has to be a rebuild rather
    // than a stale constant. `scripts/tauri.mjs` resolves the first two; the
    // rest reach cargo as this build's own environment.
    for variable in [
        "VITE_API_URL",
        "VITE_ROUTING_ENDPOINTS",
        "VITE_READ_ACCELERATOR_URL",
        "VITE_PUBLIC_GATEWAYS",
        "VITE_ENVIRONMENT",
    ] {
        println!("cargo:rerun-if-env-changed={variable}");
    }
    tauri_build::build();
}
