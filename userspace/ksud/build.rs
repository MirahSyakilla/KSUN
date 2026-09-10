use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::Command;

fn parse_version_file(path: &Path) -> Option<(u32, String)> {
    let contents = std::fs::read_to_string(path).ok()?;
    let lines: Vec<_> = contents.lines().map(str::trim).collect();
    if !lines.iter().any(|line| line.contains('=')) && lines.len() >= 2 {
        return Some((lines[0].parse().ok()?, lines[1].to_string()));
    }
    let mut code = None;
    let mut tag = None;
    for line in contents.lines() {
        if let Some(value) = line.strip_prefix("KSU_VERSION_CODE=") {
            code = value.trim().parse().ok();
        } else if let Some(value) = line.strip_prefix("KSU_VERSION_TAG=") {
            if !value.trim().is_empty() {
                tag = Some(value.trim().to_string());
            }
        }
    }
    Some((code?, tag?))
}

fn get_git_version(manifest_dir: &Path) -> Result<(u32, String), std::io::Error> {
    let git_root = String::from_utf8(
        Command::new("git")
            .current_dir(manifest_dir)
            .args(["rev-parse", "--show-toplevel"])
            .output()?
            .stdout,
    )
    .map_err(|_| std::io::Error::other("Failed to read git root"))?;
    let project_root = manifest_dir
        .join("../..")
        .canonicalize()
        .map_err(|_| std::io::Error::other("Failed to resolve project root"))?;
    if Path::new(git_root.trim()) != project_root {
        return Err(std::io::Error::other("Git root is not the KernelSU project root"));
    }

    let output = Command::new("git")
        .current_dir(manifest_dir)
        .args(["rev-list", "--count", "HEAD"])
        .output()?;

    let output = output.stdout;
    let version_code = String::from_utf8(output).expect("Failed to read git count stdout");
    let version_code: u32 = version_code
        .trim()
        .parse()
        .map_err(|_| std::io::Error::other("Failed to parse git count"))?;
    let version_code = 30000 + version_code;

    let version_name = String::from_utf8(
        Command::new("git")
            .current_dir(manifest_dir)
            .args(["describe", "--tags", "--always"])
            .output()?
            .stdout,
    )
    .map_err(|_| std::io::Error::other("Failed to read git describe stdout"))?;
    let version_name = version_name.trim().trim_start_matches('v').to_string();
    Ok((version_code, version_name))
}

fn get_version() -> (u32, String) {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    if let (Ok(code), Ok(tag)) = (
        env::var("KSU_VERSION_OVERRIDE"),
        env::var("KSU_VERSION_TAG_OVERRIDE"),
    ) {
        if let Ok(code) = code.parse() {
            return (code, tag);
        }
    }
    if let Ok(version) = get_git_version(manifest_dir) {
        return version;
    }
    if let Some((code, tag)) = parse_version_file(&manifest_dir.join("../../kernel/VERSION")) {
        return (code, tag.trim_start_matches('v').to_string());
    }
    if let Some((count, tag)) =
        parse_version_file(&manifest_dir.join("../../kernel/.ksu_git_version"))
    {
        return (30000 + count, tag.trim_start_matches('v').to_string());
    }
    println!(
        "cargo:warning=KernelSU-Next version metadata unavailable, using unknown build marker"
    );
    (1, "v0.0.0".to_string())
}

fn configure_bindgen() {
    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("src/ksu_uapi.h")
        .clang_args(["-x", "c++", "-I../../", "-I/usr/include"])
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = std::path::PathBuf::from(env::var("OUT_DIR").unwrap());
    // for debug, uncomment below
    // let out_path = std::path::PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

fn main() {
    println!("cargo:rerun-if-env-changed=KSU_VERSION_OVERRIDE");
    println!("cargo:rerun-if-env-changed=KSU_VERSION_TAG_OVERRIDE");
    println!("cargo:rerun-if-changed=../../kernel/VERSION");
    println!("cargo:rerun-if-changed=../../kernel/.ksu_git_version");
    let (code, name) = get_version();
    let out_dir = env::var("OUT_DIR").expect("Failed to get $OUT_DIR");
    let out_dir = Path::new(&out_dir);
    File::create(Path::new(out_dir).join("VERSION_CODE"))
        .expect("Failed to create VERSION_CODE")
        .write_all(code.to_string().as_bytes())
        .expect("Failed to write VERSION_CODE");

    File::create(Path::new(out_dir).join("VERSION_NAME"))
        .expect("Failed to create VERSION_NAME")
        .write_all(name.trim().as_bytes())
        .expect("Failed to write VERSION_NAME");

    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("CARGO_CFG_TARGET_OS not set");
    if target_os == "android" {
        configure_bindgen();
    }
}
