fn main() {
    // FUSE-T's `libfuse-t.dylib` has an `@rpath` install name, and the matching
    // `-Wl,-rpath` its `fuse-t.pc` carries is parsed by the `pkg-config` crate
    // but never forwarded to rustc. A dependency build script's link arg does
    // not reach the final link, so every package that links the adapter states
    // it — which libfuse won is still decided in the vendored `fuser` script.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    match pkg_config::Config::new()
        .cargo_metadata(false)
        .probe("fuse-t")
    {
        Ok(lib) => {
            for path in &lib.link_paths {
                println!("cargo:rustc-link-arg=-Wl,-rpath,{}", path.display());
            }
        }
        // Loud, because the binary still links and only fails at load.
        Err(e) => println!("cargo:warning=fuse-t.pc not found, linking no rpath: {e}"),
    }
}
