fn main() {
    tauri_build::build();
    #[cfg(target_os = "windows")]
    {
        winfsp::build::winfsp_link_delayload();
    }
}
