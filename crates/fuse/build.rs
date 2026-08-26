fn main() {
    // FUSE-T's `libfuse-t.dylib` has an `@rpath` install name, and the matching
    // `-Wl,-rpath` its `fuse-t.pc` carries is parsed by the `pkg-config` crate
    // but never forwarded to rustc. A dependency build script's link arg never
    // reaches the final link, so each package that links the adapter re-probes
    // for the search path — which libfuse won is still decided in one place,
    // the vendored `fuser` build script.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    if let Ok(lib) = pkg_config::Config::new()
        .cargo_metadata(false)
        .probe("fuse-t")
    {
        for path in &lib.link_paths {
            println!("cargo:rustc-link-arg=-Wl,-rpath,{}", path.display());
        }
    }
}
