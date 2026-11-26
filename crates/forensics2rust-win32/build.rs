use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=app.manifest");
    println!("cargo:rerun-if-changed=app.rc");
    println!("cargo:rerun-if-changed=icon.rc");
    println!("cargo:rerun-if-changed=app.ico");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        return;
    }

    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_default());

    if target_env == "msvc" {
        #[cfg(windows)]
        {
            let icon_rc = manifest_dir.join("icon.rc");
            let app_ico = manifest_dir.join("app.ico");
            if icon_rc.is_file() && app_ico.is_file() {
                embed_resource::compile("icon.rc", embed_resource::NONE)
                    .manifest_optional()
                    .unwrap();
            }
        }
        let manifest = manifest_dir.join("app.manifest");
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
        return;
    }

    if target_env == "gnu" {
        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap_or_default());
        let obj_path = out_dir.join("app_manifest.o");
        let rc_path = manifest_dir.join("app.rc");

        for tool in ["windres", "x86_64-w64-mingw32-windres"] {
            if let Ok(status) = Command::new(tool)
                .args([
                    "-I",
                    &manifest_dir.display().to_string(),
                    "-i",
                    &rc_path.display().to_string(),
                    "-o",
                    &obj_path.display().to_string(),
                ])
                .status()
                && status.success()
                && obj_path.is_file()
            {
                // Applies to both [[bin]] and `cargo test` binaries so COMCTL32 v6 loads without 0xc0000139.
                println!("cargo:rustc-link-arg={}", obj_path.display());
                return;
            }
        }
        println!("cargo:warning=windres not found; Common Controls v6 manifest was not embedded");
    }
}
