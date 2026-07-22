fn main() {
    // libfuse-t's install name is @rpath-relative and cargo drops the
    // -Wl,-rpath from fuse-t.pc, so re-probe and emit the rpath here, on the
    // binary's own package — a dependency build script's rustc-link-arg never
    // reaches the final link. The library selection itself happens in the
    // vendored fuser's build script.
    if cfg!(target_os = "macos")
        && let Ok(lib) = pkg_config::Config::new().probe("fuse-t")
    {
        for p in &lib.link_paths {
            println!("cargo:rustc-link-arg=-Wl,-rpath,{}", p.display());
        }
    }
}
