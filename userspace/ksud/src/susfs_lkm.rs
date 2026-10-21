// Loader for the SUSFS guard LKM (susfs_guard_lkm.ko).
//
// Upstream KernelSU-Next ships SUSFS as a loadable kernel module that is built
// out of tree; this fork carries that module in kernel/susfs_lkm/ (built by
// tools/build/build_susfs_lkm.sh) and this file is its loader.
//
// The module is NOT loaded with a plain insmod.  It imports kernel symbols the
// kernel does not export (saved_boot_config, task_work_add, init_mm,
// copy_to_kernel_nofault, __set_fixmap), so the image has to be absolutized
// from /proc/kallsyms before init_module() runs - ksuinit::load_module() does
// exactly that, and the module's own imports_guard.c refuses the load when
// any import did not get a real kernel address.
//
// This fork's in-tree hookless SUSFS (the one kernelsu.ko implements, and the
// one userspace/ksud/src/susfsd.rs talks to) and the standalone module are
// ALTERNATIVES: both implement SUSFS on the same hooks (the reboot supercall,
// the LSM slot patcher, the stat/statx probes).  Only one of them may be live
// on a device, so the loader refuses to load the module while a SUSFS
// implementation is already answering the supercall.

use std::ffi::CString;
use std::path::Path;

use anyhow::{Context, Result, anyhow, ensure};
use const_format::concatcp;
use log::{info, warn};

use crate::defs;

const MODULE_NAME: &str = "susfs_guard_lkm";
// Where the operator can place the module on the device when it is not
// shipped as an embedded asset.
const MODULE_FILE_PATH: &str = concatcp!(defs::WORKING_DIR, "susfs_guard_lkm.ko");

const AUTOLOAD_CONFIG_MODULE_ID: &str = "internal.ksud.susfs_lkm";
const AUTOLOAD_ENABLED_CONFIG_KEY: &str = "autoload.enabled";
const AUTOLOAD_FALLBACK_KMI_CONFIG_KEY: &str = "autoload.fallback_kmi";

struct AutoLoadConfig {
    enabled: bool,
    fallback_kmi: Option<String>,
}

fn validate_kmi(kmi: &str) -> Result<()> {
    ensure!(
        !kmi.is_empty()
            && kmi.len() <= 64
            && kmi.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
            }),
        "Invalid KMI '{kmi}'"
    );
    Ok(())
}

fn read_autoload_config() -> Result<AutoLoadConfig> {
    let enabled = crate::module_config::get_config_value(
        AUTOLOAD_CONFIG_MODULE_ID,
        AUTOLOAD_ENABLED_CONFIG_KEY,
        crate::module_config::ConfigType::Persist,
    )?;
    let fallback_kmi = crate::module_config::get_config_value(
        AUTOLOAD_CONFIG_MODULE_ID,
        AUTOLOAD_FALLBACK_KMI_CONFIG_KEY,
        crate::module_config::ConfigType::Persist,
    )?;
    if let Some(kmi) = &fallback_kmi {
        validate_kmi(kmi)?;
    }

    Ok(AutoLoadConfig {
        enabled: enabled
            .as_deref()
            .is_some_and(crate::module_config::parse_bool_config),
        fallback_kmi,
    })
}

pub fn autoload_enabled() -> Result<bool> {
    Ok(read_autoload_config()?.enabled)
}

pub fn set_autoload(enabled: bool, kmi: Option<&str>) -> Result<()> {
    if !enabled {
        crate::module_config::set_config_value(
            AUTOLOAD_CONFIG_MODULE_ID,
            AUTOLOAD_ENABLED_CONFIG_KEY,
            "false",
            crate::module_config::ConfigType::Persist,
        )
        .context("Failed to disable SUSFS auto-load")?;
        println!("SUSFS auto-load disabled");
        return Ok(());
    }

    anyhow::ensure!(
        cfg!(target_arch = "aarch64"),
        "SUSFS guard LKM is only available for arm64"
    );

    let kmi = match kmi {
        Some(kmi) => kmi.to_owned(),
        None => crate::boot_patch::get_current_kmi().context(
            "Failed to detect kernel KMI; specify it with `ksud susfs autoload enable --kmi <KMI>`",
        )?,
    };
    validate_kmi(&kmi)?;

    // Refuse to arm an autoload that can never work: the image has to be
    // reachable for that KMI.
    module_image(&kmi)?;

    crate::module_config::set_config_value(
        AUTOLOAD_CONFIG_MODULE_ID,
        AUTOLOAD_FALLBACK_KMI_CONFIG_KEY,
        &kmi,
        crate::module_config::ConfigType::Persist,
    )
    .context("Failed to save SUSFS auto-load config")?;
    crate::module_config::set_config_value(
        AUTOLOAD_CONFIG_MODULE_ID,
        AUTOLOAD_ENABLED_CONFIG_KEY,
        "true",
        crate::module_config::ConfigType::Persist,
    )
    .context("Failed to save SUSFS auto-load config")?;

    println!("SUSFS auto-load enabled (KMI fallback: {kmi})");
    Ok(())
}

fn module_is_loaded() -> bool {
    Path::new("/sys/module").join(MODULE_NAME).exists()
}

// The module image: the embedded asset for the KMI when the build shipped one,
// otherwise the file the operator placed on the device.
fn module_image(kmi: &str) -> Result<Vec<u8>> {
    let asset_name = format!("{kmi}_susfs_guard_lkm.ko");
    if let Ok(data) = crate::assets::get_asset_data(&asset_name) {
        return Ok(data.into_owned());
    }

    let path = Path::new(MODULE_FILE_PATH);
    if path.exists() {
        return std::fs::read(path)
            .with_context(|| format!("Failed to read {MODULE_FILE_PATH}"));
    }

    Err(anyhow!(
        "SUSFS guard LKM not found: neither the embedded asset {asset_name} nor {MODULE_FILE_PATH} is available"
    ))
}

pub fn load_if_autoload_enabled() -> Result<()> {
    let config = read_autoload_config()?;
    if !config.enabled {
        return Ok(());
    }
    if !cfg!(target_arch = "aarch64") {
        warn!("SUSFS auto-load is enabled, but the SUSFS LKM is only available for arm64");
        return Ok(());
    }
    if module_is_loaded() {
        info!("SUSFS guard LKM is already loaded; skipping the auto-load");
        return Ok(());
    }
    if let Some(version) = crate::susfsd::detected_version() {
        warn!("SUSFS {version} is already available; skipping the guard LKM load (the hookless SUSFS and the guard LKM are alternatives)");
        return Ok(());
    }

    let kmi = crate::boot_patch::get_current_kmi()
        .ok()
        .or(config.fallback_kmi);
    let Some(kmi) = kmi else {
        warn!("SUSFS auto-load is enabled, but KMI detection failed and no fallback KMI is saved");
        return Ok(());
    };

    if let Err(error) = load(Some(&kmi)) {
        warn!("Failed to auto-load SUSFS guard LKM for KMI {kmi}: {error:#}");
    }
    Ok(())
}

pub fn load(kmi: Option<&str>) -> Result<()> {
    anyhow::ensure!(
        cfg!(target_arch = "aarch64"),
        "SUSFS guard LKM is only available for arm64"
    );

    if module_is_loaded() {
        println!("SUSFS guard LKM is already loaded");
        return Ok(());
    }
    if let Some(version) = crate::susfsd::detected_version() {
        return Err(anyhow!(
            "SUSFS {version} is already available on this kernel: the in-tree hookless SUSFS and the guard LKM are alternatives, so the LKM was not loaded"
        ));
    }

    let kmi = match kmi {
        Some(kmi) => kmi.to_owned(),
        None => crate::boot_patch::get_current_kmi().context(
            "Failed to detect kernel KMI; specify it explicitly with `ksud susfs load --kmi <KMI>`",
        )?,
    };
    validate_kmi(&kmi)?;

    let module_data = module_image(&kmi)?;
    let params = CString::new("").expect("empty module parameters are valid");

    info!("Loading SUSFS guard LKM for KMI {kmi}");
    crate::debug::load_module_image(&module_data, &params)
        .context("Failed to load SUSFS guard LKM")?;
    println!("Loaded SUSFS guard LKM for KMI {kmi}");
    Ok(())
}

pub fn unload() -> Result<()> {
    if !module_is_loaded() {
        println!("SUSFS guard LKM is not loaded");
        return Ok(());
    }
    let name = CString::new(MODULE_NAME).expect("the module name has no interior nul");
    rustix::system::delete_module(&name, 0).context("Failed to unload SUSFS guard LKM")?;
    println!("Unloaded SUSFS guard LKM");
    Ok(())
}
