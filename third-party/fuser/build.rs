fn main() {
    // Register rustc cfg for switching between mount implementations.
    // When fuser MSRV is updated to v1.77 or above, we should switch from 'cargo:' to 'cargo::' syntax.
    println!(
        "cargo:rustc-check-cfg=cfg(fuser_mount_impl, values(\"pure-rust\", \"libfuse2\", \"libfuse3\"))"
    );

    // fuser is Unix-only. On Windows the crate is resolved by [patch.crates-io]
    // but compiles as an empty crate (lib.rs gates all content behind #[cfg(unix)]).
    #[cfg(not(unix))]
    return;

    #[cfg(unix)]
    unix_build();
}

#[cfg(unix)]
fn unix_build() {
    #[cfg(all(not(feature = "libfuse"), not(target_os = "linux")))]
    unimplemented!("Building without libfuse is only supported on Linux");

    #[cfg(not(feature = "libfuse"))]
    {
        println!("cargo:rustc-cfg=fuser_mount_impl=\"pure-rust\"");
    }
    #[cfg(feature = "libfuse")]
    {
        if cfg!(target_os = "macos") {
            // CipherBox patch: prefer FUSE-T. Its fuse-t.pc reports the FUSE-T
            // version (1.x), not a libfuse API version, so no version floor;
            // libfuse-t exports fuse_mount_compat25 (plain libfuse2 ABI, no
            // macfuse-4-compat). Probing "fuse" first would link macFUSE when
            // both are installed and trigger its kext.
            if pkg_config::Config::new()
                .probe("fuse-t")
                .map_err(|e| eprintln!("{e}"))
                .is_ok()
            {
                println!("cargo:rustc-cfg=fuser_mount_impl=\"libfuse2\"");
            } else if pkg_config::Config::new()
                .atleast_version("2.6.0")
                .probe("fuse") // for macFUSE 4.x
                .map_err(|e| eprintln!("{e}"))
                .is_ok()
            {
                println!("cargo:rustc-cfg=fuser_mount_impl=\"libfuse2\"");
                println!("cargo:rustc-cfg=feature=\"macfuse-4-compat\"");
            } else {
                pkg_config::Config::new()
                    .atleast_version("2.6.0")
                    .probe("osxfuse") // for osxfuse 3.x
                    .map_err(|e| eprintln!("{e}"))
                    .unwrap();
                println!("cargo:rustc-cfg=fuser_mount_impl=\"libfuse2\"");
            }
        } else {
            // First try to link with libfuse3
            if pkg_config::Config::new()
                .atleast_version("3.0.0")
                .probe("fuse3")
                .map_err(|e| eprintln!("{e}"))
                .is_ok()
            {
                println!("cargo:rustc-cfg=fuser_mount_impl=\"libfuse3\"");
            } else {
                // Fallback to libfuse
                pkg_config::Config::new()
                    .atleast_version("2.6.0")
                    .probe("fuse")
                    .map_err(|e| eprintln!("{e}"))
                    .unwrap();
                println!("cargo:rustc-cfg=fuser_mount_impl=\"libfuse2\"");
            }
        }
    }
}
