// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::io::Read;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::fetch::apt;

// ---------------------------------------------------------------------------
// Serde structs for socorro crash report JSON
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SocorroReport {
    pub product: Option<String>,
    pub version: Option<String>,
    pub release_channel: Option<String>,
    pub build: Option<String>,
    /// Top-level crashing thread index (integer).
    pub crashing_thread: Option<usize>,
    pub json_dump: Option<JsonDump>,
}

#[derive(Deserialize)]
pub struct JsonDump {
    pub threads: Option<Vec<CrashThread>>,
    pub modules: Option<Vec<CrashModule>>,
    pub lsb_release: Option<LsbRelease>,
}

#[derive(Deserialize)]
pub struct CrashThread {
    pub frames: Option<Vec<CrashFrame>>,
}

#[derive(Deserialize)]
pub struct CrashFrame {
    pub module: Option<String>,
    pub module_offset: Option<String>,
    #[allow(dead_code)]
    pub function: Option<String>,
}

#[derive(Deserialize)]
pub struct CrashModule {
    pub debug_file: Option<String>,
    pub debug_id: Option<String>,
    pub code_id: Option<String>,
    pub filename: Option<String>,
}

#[derive(Deserialize)]
pub struct LsbRelease {
    pub id: Option<String>,
    pub codename: Option<String>,
}

// ---------------------------------------------------------------------------
// Resolved result
// ---------------------------------------------------------------------------

/// All values needed from a socorro crash report to fill DisasmArgs.
#[derive(Debug)]
pub struct ResolvedCrashFrame {
    pub debug_file: String,
    pub debug_id: String,
    pub code_file: Option<String>,
    pub code_id: Option<String>,
    pub module_offset: Option<String>,
    pub version: Option<String>,
    pub channel: Option<String>,
    pub build_id: Option<String>,
    pub product: Option<String>,
    pub distro: Option<String>,
    pub enable_apt: bool,
    pub enable_pacman: bool,
    pub snap_names: Vec<String>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse socorro JSON from a file path or `"-"` for stdin.
/// Extract the frame at `frame_index` from the crashing thread.
///
/// When `debug_file_override` is `Some`, the module is looked up by that name
/// (matching the `debug_file` field in `json_dump.modules`) instead of the
/// frame's module. The crash frame's `module_offset` is cleared since it
/// belongs to the frame's module, not the overridden one.
pub fn resolve_crash_frame(
    path: &str,
    frame_index: usize,
    debug_file_override: Option<&str>,
) -> Result<ResolvedCrashFrame> {
    let json_text = if path == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .lock()
            .read_to_string(&mut buf)
            .context("reading socorro JSON from stdin")?;
        buf
    } else {
        std::fs::read_to_string(path)
            .with_context(|| format!("reading socorro JSON from {path}"))?
    };

    let report: SocorroReport = serde_json::from_str(&json_text).context("parsing socorro JSON")?;

    resolve_from_report(&report, frame_index, debug_file_override)
}

/// Find a module in the modules list by `debug_file` name (exact match).
fn find_module_in_list<'a>(modules: &'a [CrashModule], name: &str) -> Option<&'a CrashModule> {
    modules
        .iter()
        .find(|m| m.debug_file.as_deref() == Some(name))
}

/// Core resolution logic, separated from I/O for testability.
fn resolve_from_report(
    report: &SocorroReport,
    frame_index: usize,
    debug_file_override: Option<&str>,
) -> Result<ResolvedCrashFrame> {
    let json_dump = report
        .json_dump
        .as_ref()
        .context("socorro JSON missing 'json_dump' field")?;

    let modules = json_dump
        .modules
        .as_ref()
        .context("socorro JSON missing 'json_dump.modules'")?;

    // Look up the target module: override name if provided, otherwise frame's module.
    let (module, module_offset) = if let Some(override_name) = debug_file_override {
        // Module override: look up directly from modules list, skip frame lookup entirely.
        // The crash frame offset belongs to the frame's module, not the override.
        let m = find_module_in_list(modules, override_name).with_context(|| {
            format!(
                "module '{override_name}' not found in json_dump.modules (checked debug_file field)"
            )
        })?;
        (m, None)
    } else {
        // Normal path: resolve the frame, then look up its module.
        let crashing_thread_idx = report
            .crashing_thread
            .context("socorro JSON missing 'crashing_thread' (top-level integer field)")?;

        let threads = json_dump
            .threads
            .as_ref()
            .context("socorro JSON missing 'json_dump.threads'")?;

        let thread = threads.get(crashing_thread_idx).with_context(|| {
            format!(
                "crashing thread index {crashing_thread_idx} out of range (have {} threads)",
                threads.len()
            )
        })?;

        let frames = thread
            .frames
            .as_ref()
            .context("crashing thread has no 'frames' array")?;

        let frame = frames.get(frame_index).with_context(|| {
            format!(
                "frame index {frame_index} out of range (crashing thread has {} frames)",
                frames.len()
            )
        })?;

        let frame_module_name = frame
            .module
            .as_deref()
            .context("selected frame has no 'module' field")?;
        let m = modules
            .iter()
            .find(|m| m.filename.as_deref() == Some(frame_module_name))
            .with_context(|| {
                format!(
                    "module '{}' from frame not found in json_dump.modules",
                    frame_module_name
                )
            })?;
        (m, frame.module_offset.clone())
    };

    let debug_file = module
        .debug_file
        .clone()
        .context("matching module has no 'debug_file'")?;
    let debug_id = module
        .debug_id
        .clone()
        .context("matching module has no 'debug_id'")?;

    // Map product name
    let product = report.product.as_deref().map(|p| match p {
        "Fenix" => "fenix".to_string(),
        "Focus" => "focus".to_string(),
        "Thunderbird" => "thunderbird".to_string(),
        _ => "firefox".to_string(),
    });

    // Distro detection from lsb_release
    let lsb = json_dump.lsb_release.as_ref();
    let distro = lsb.and_then(|l| l.codename.clone());
    let lsb_id_raw = lsb.and_then(|l| l.id.clone());

    let enable_apt = distro
        .as_deref()
        .map(|d| apt::resolve_repo_config(d).is_some())
        .unwrap_or(false);

    // Case-insensitive comparison: real socorro data uses "arch" (lowercase)
    let enable_pacman = lsb_id_raw.as_deref().is_some_and(|id| {
        let lower = id.to_ascii_lowercase();
        matches!(
            lower.as_str(),
            "arch" | "cachyos" | "manjarolinux" | "endeavouros"
        )
    });

    // Snap guessing for Ubuntu snap-based Firefox installs
    let snap_names = guess_snap_names(distro.as_deref());

    Ok(ResolvedCrashFrame {
        debug_file,
        debug_id,
        code_file: module.filename.clone(),
        code_id: module.code_id.clone(),
        module_offset,
        version: report.version.clone(),
        channel: report.release_channel.clone(),
        build_id: report.build.clone(),
        product,
        distro,
        enable_apt,
        enable_pacman,
        snap_names,
    })
}

/// Guess snap runtime package names for Ubuntu codenames where Firefox is
/// distributed as a snap (22.04 jammy and later).
fn guess_snap_names(codename: Option<&str>) -> Vec<String> {
    match codename {
        // Ubuntu 22.04 cycle (GNOME 42 SDK)
        Some("jammy" | "kinetic" | "lunar" | "mantic") => {
            vec!["gnome-42-2204-sdk".to_string(), "core22".to_string()]
        }
        // Ubuntu 24.04 cycle and later (GNOME 46 SDK)
        Some("noble" | "oracular" | "plucky") => {
            vec!["gnome-46-2404-sdk".to_string(), "core24".to_string()]
        }
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_report(json: &str) -> SocorroReport {
        serde_json::from_str(json).expect("test JSON must parse")
    }

    const FULL_REPORT: &str = r#"{
        "product": "Firefox",
        "version": "128.0.3",
        "release_channel": "release",
        "build": "20240726144536",
        "crashing_thread": 0,
        "json_dump": {
            "threads": [{
                "frames": [{
                    "module": "xul.dll",
                    "module_offset": "0x0144c8d2",
                    "function": "SomeFunction"
                }, {
                    "module": "xul.dll",
                    "module_offset": "0x00abcdef",
                    "function": "CallerFunction"
                }]
            }],
            "modules": [{
                "debug_file": "xul.pdb",
                "debug_id": "EE20BD9ABD8D048B4C4C44205044422E1",
                "code_id": "68d1a3cd87be000",
                "filename": "xul.dll"
            }, {
                "debug_file": "ntdll.pdb",
                "debug_id": "08A413EE85E91D0377BA33DC3A2641941",
                "code_id": "5b6dddee267000",
                "filename": "ntdll.dll"
            }]
        }
    }"#;

    #[test]
    fn test_valid_crash_report() {
        let report = make_report(FULL_REPORT);
        let resolved = resolve_from_report(&report, 0, None).unwrap();
        assert_eq!(resolved.debug_file, "xul.pdb");
        assert_eq!(resolved.debug_id, "EE20BD9ABD8D048B4C4C44205044422E1");
        assert_eq!(resolved.code_file.as_deref(), Some("xul.dll"));
        assert_eq!(resolved.code_id.as_deref(), Some("68d1a3cd87be000"));
        assert_eq!(resolved.module_offset.as_deref(), Some("0x0144c8d2"));
        assert_eq!(resolved.version.as_deref(), Some("128.0.3"));
        assert_eq!(resolved.channel.as_deref(), Some("release"));
        assert_eq!(resolved.build_id.as_deref(), Some("20240726144536"));
        assert_eq!(resolved.product.as_deref(), Some("firefox"));
        assert!(!resolved.enable_apt);
        assert!(!resolved.enable_pacman);
        assert!(resolved.snap_names.is_empty());
    }

    #[test]
    fn test_frame_1() {
        let report = make_report(FULL_REPORT);
        let resolved = resolve_from_report(&report, 1, None).unwrap();
        // Frame 1 also references xul.dll
        assert_eq!(resolved.debug_file, "xul.pdb");
        assert_eq!(resolved.module_offset.as_deref(), Some("0x00abcdef"));
    }

    #[test]
    fn test_frame_out_of_range() {
        let report = make_report(FULL_REPORT);
        let err = resolve_from_report(&report, 99, None).unwrap_err();
        assert!(err.to_string().contains("frame index 99 out of range"));
    }

    #[test]
    fn test_missing_json_dump() {
        let report = make_report(r#"{"product": "Firefox"}"#);
        let err = resolve_from_report(&report, 0, None).unwrap_err();
        assert!(err.to_string().contains("json_dump"));
    }

    #[test]
    fn test_missing_threads() {
        let report = make_report(
            r#"{
            "crashing_thread": 0,
            "json_dump": {
                "modules": [{"debug_file": "xul.pdb", "debug_id": "AA", "filename": "xul.dll"}]
            }
        }"#,
        );
        let err = resolve_from_report(&report, 0, None).unwrap_err();
        assert!(err.to_string().contains("threads"));
    }

    #[test]
    fn test_module_not_found() {
        let report = make_report(
            r#"{
            "crashing_thread": 0,
            "json_dump": {
                "threads": [{
                    "frames": [{
                        "module": "unknown.dll",
                        "module_offset": "0x100"
                    }]
                }],
                "modules": [{
                    "debug_file": "xul.pdb",
                    "debug_id": "AABB",
                    "filename": "xul.dll"
                }]
            }
        }"#,
        );
        let err = resolve_from_report(&report, 0, None).unwrap_err();
        assert!(err.to_string().contains("unknown.dll"));
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_missing_optional_fields() {
        let report = make_report(
            r#"{
            "crashing_thread": 0,
            "json_dump": {
                "threads": [{
                    "frames": [{
                        "module": "xul.dll",
                        "module_offset": "0x100"
                    }]
                }],
                "modules": [{
                    "debug_file": "xul.pdb",
                    "debug_id": "AABB",
                    "filename": "xul.dll"
                }]
            }
        }"#,
        );
        let resolved = resolve_from_report(&report, 0, None).unwrap();
        assert_eq!(resolved.debug_file, "xul.pdb");
        assert!(resolved.code_id.is_none());
        assert!(resolved.version.is_none());
        assert!(resolved.channel.is_none());
        assert!(resolved.build_id.is_none());
        assert!(resolved.product.is_none());
        assert!(resolved.distro.is_none());
    }

    #[test]
    fn test_fenix_product() {
        let report = make_report(
            r#"{
            "product": "Fenix",
            "version": "128.0",
            "release_channel": "release",
            "crashing_thread": 0,
            "json_dump": {
                "threads": [{
                    "frames": [{
                        "module": "libxul.so",
                        "module_offset": "0x100"
                    }]
                }],
                "modules": [{
                    "debug_file": "libxul.so",
                    "debug_id": "AABB",
                    "filename": "libxul.so"
                }]
            }
        }"#,
        );
        let resolved = resolve_from_report(&report, 0, None).unwrap();
        assert_eq!(resolved.product.as_deref(), Some("fenix"));
    }

    #[test]
    fn test_focus_product() {
        let report = make_report(
            r#"{
            "product": "Focus",
            "crashing_thread": 0,
            "json_dump": {
                "threads": [{
                    "frames": [{"module": "libxul.so", "module_offset": "0x1"}]
                }],
                "modules": [{"debug_file": "libxul.so", "debug_id": "AA", "filename": "libxul.so"}]
            }
        }"#,
        );
        let resolved = resolve_from_report(&report, 0, None).unwrap();
        assert_eq!(resolved.product.as_deref(), Some("focus"));
    }

    #[test]
    fn test_thunderbird_product() {
        let report = make_report(
            r#"{
            "product": "Thunderbird",
            "crashing_thread": 0,
            "json_dump": {
                "threads": [{
                    "frames": [{"module": "libxul.so", "module_offset": "0x1"}]
                }],
                "modules": [{"debug_file": "libxul.so", "debug_id": "AA", "filename": "libxul.so"}]
            }
        }"#,
        );
        let resolved = resolve_from_report(&report, 0, None).unwrap();
        assert_eq!(resolved.product.as_deref(), Some("thunderbird"));
    }

    #[test]
    fn test_ubuntu_noble_apt_and_snap() {
        let report = make_report(
            r#"{
            "product": "Firefox",
            "crashing_thread": 0,
            "json_dump": {
                "threads": [{
                    "frames": [{"module": "libglib-2.0.so.0", "module_offset": "0x1"}]
                }],
                "modules": [{"debug_file": "libglib-2.0.so.0", "debug_id": "AA", "filename": "libglib-2.0.so.0"}],
                "lsb_release": {"id": "Ubuntu", "codename": "noble"}
            }
        }"#,
        );
        let resolved = resolve_from_report(&report, 0, None).unwrap();
        assert_eq!(resolved.distro.as_deref(), Some("noble"));
        assert!(resolved.enable_apt);
        assert!(!resolved.enable_pacman);
        assert_eq!(resolved.snap_names, vec!["gnome-46-2404-sdk", "core24"]);
    }

    #[test]
    fn test_ubuntu_jammy_snap() {
        let report = make_report(
            r#"{
            "crashing_thread": 0,
            "json_dump": {
                "threads": [{
                    "frames": [{"module": "libglib-2.0.so.0", "module_offset": "0x1"}]
                }],
                "modules": [{"debug_file": "libglib-2.0.so.0", "debug_id": "AA", "filename": "libglib-2.0.so.0"}],
                "lsb_release": {"id": "Ubuntu", "codename": "jammy"}
            }
        }"#,
        );
        let resolved = resolve_from_report(&report, 0, None).unwrap();
        assert!(resolved.enable_apt);
        assert_eq!(resolved.snap_names, vec!["gnome-42-2204-sdk", "core22"]);
    }

    #[test]
    fn test_ubuntu_bionic_no_snap() {
        let report = make_report(
            r#"{
            "crashing_thread": 0,
            "json_dump": {
                "threads": [{
                    "frames": [{"module": "libxul.so", "module_offset": "0x1"}]
                }],
                "modules": [{"debug_file": "libxul.so", "debug_id": "AA", "filename": "libxul.so"}],
                "lsb_release": {"id": "Ubuntu", "codename": "bionic"}
            }
        }"#,
        );
        let resolved = resolve_from_report(&report, 0, None).unwrap();
        assert!(resolved.enable_apt);
        assert!(resolved.snap_names.is_empty());
    }

    #[test]
    fn test_ubuntu_xenial_no_snap() {
        let report = make_report(
            r#"{
            "crashing_thread": 0,
            "json_dump": {
                "threads": [{
                    "frames": [{"module": "libxul.so", "module_offset": "0x1"}]
                }],
                "modules": [{"debug_file": "libxul.so", "debug_id": "AA", "filename": "libxul.so"}],
                "lsb_release": {"id": "Ubuntu", "codename": "xenial"}
            }
        }"#,
        );
        let resolved = resolve_from_report(&report, 0, None).unwrap();
        assert!(resolved.enable_apt);
        assert!(resolved.snap_names.is_empty());
    }

    #[test]
    fn test_arch_linux_pacman() {
        let report = make_report(
            r#"{
            "crashing_thread": 0,
            "json_dump": {
                "threads": [{
                    "frames": [{"module": "libxul.so", "module_offset": "0x1"}]
                }],
                "modules": [{"debug_file": "libxul.so", "debug_id": "AA", "filename": "libxul.so"}],
                "lsb_release": {"id": "Arch", "codename": "rolling"}
            }
        }"#,
        );
        let resolved = resolve_from_report(&report, 0, None).unwrap();
        assert!(!resolved.enable_apt);
        assert!(resolved.enable_pacman);
        assert!(resolved.snap_names.is_empty());
    }

    #[test]
    fn test_cachyos_pacman() {
        let report = make_report(
            r#"{
            "crashing_thread": 0,
            "json_dump": {
                "threads": [{
                    "frames": [{"module": "libxul.so", "module_offset": "0x1"}]
                }],
                "modules": [{"debug_file": "libxul.so", "debug_id": "AA", "filename": "libxul.so"}],
                "lsb_release": {"id": "CachyOS"}
            }
        }"#,
        );
        let resolved = resolve_from_report(&report, 0, None).unwrap();
        assert!(resolved.enable_pacman);
    }

    #[test]
    fn test_arch_linux_lowercase_id() {
        // Real socorro data uses lowercase "arch" for lsb_release.id
        let report = make_report(
            r#"{
            "crashing_thread": 0,
            "json_dump": {
                "threads": [{
                    "frames": [{"module": "libc.so.6", "module_offset": "0x1"}]
                }],
                "modules": [{"debug_file": "libc.so.6", "debug_id": "AA", "filename": "libc.so.6"}],
                "lsb_release": {"id": "arch", "codename": ""}
            }
        }"#,
        );
        let resolved = resolve_from_report(&report, 0, None).unwrap();
        assert!(resolved.enable_pacman);
        assert!(!resolved.enable_apt);
    }

    #[test]
    fn test_debian_bookworm_apt() {
        let report = make_report(
            r#"{
            "crashing_thread": 0,
            "json_dump": {
                "threads": [{
                    "frames": [{"module": "libglib-2.0.so.0", "module_offset": "0x1"}]
                }],
                "modules": [{"debug_file": "libglib-2.0.so.0", "debug_id": "AA", "filename": "libglib-2.0.so.0"}],
                "lsb_release": {"id": "debian", "codename": "bookworm"}
            }
        }"#,
        );
        let resolved = resolve_from_report(&report, 0, None).unwrap();
        assert_eq!(resolved.distro.as_deref(), Some("bookworm"));
        assert!(resolved.enable_apt);
        assert!(!resolved.enable_pacman);
        assert!(resolved.snap_names.is_empty());
    }

    #[test]
    fn test_no_lsb_release() {
        let report = make_report(
            r#"{
            "crashing_thread": 0,
            "json_dump": {
                "threads": [{
                    "frames": [{"module": "xul.dll", "module_offset": "0x1"}]
                }],
                "modules": [{"debug_file": "xul.pdb", "debug_id": "AA", "filename": "xul.dll"}]
            }
        }"#,
        );
        let resolved = resolve_from_report(&report, 0, None).unwrap();
        assert!(resolved.distro.is_none());
        assert!(!resolved.enable_apt);
        assert!(!resolved.enable_pacman);
        assert!(resolved.snap_names.is_empty());
    }

    // -----------------------------------------------------------------------
    // Module override tests (--debug-file with --socorro-json)
    // -----------------------------------------------------------------------

    #[test]
    fn test_override_by_debug_file() {
        let report = make_report(FULL_REPORT);
        // Frame 0 is xul.dll, but override to ntdll.pdb → gets ntdll's IDs
        let resolved = resolve_from_report(&report, 0, Some("ntdll.pdb")).unwrap();
        assert_eq!(resolved.debug_file, "ntdll.pdb");
        assert_eq!(resolved.debug_id, "08A413EE85E91D0377BA33DC3A2641941");
        assert_eq!(resolved.code_file.as_deref(), Some("ntdll.dll"));
        assert_eq!(resolved.code_id.as_deref(), Some("5b6dddee267000"));
    }

    #[test]
    fn test_override_by_filename_not_matched() {
        let report = make_report(FULL_REPORT);
        // filename (ntdll.dll) is NOT matched — only debug_file (ntdll.pdb) works
        let err = resolve_from_report(&report, 0, Some("ntdll.dll")).unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_override_clears_module_offset() {
        let report = make_report(FULL_REPORT);
        // Without override, frame 0 has module_offset
        let no_override = resolve_from_report(&report, 0, None).unwrap();
        assert_eq!(no_override.module_offset.as_deref(), Some("0x0144c8d2"));
        // With override, module_offset is cleared (crash offset belongs to frame's module)
        let with_override = resolve_from_report(&report, 0, Some("ntdll.pdb")).unwrap();
        assert!(with_override.module_offset.is_none());
    }

    #[test]
    fn test_override_module_not_found() {
        let report = make_report(FULL_REPORT);
        let err = resolve_from_report(&report, 0, Some("nonexistent.dll")).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("nonexistent.dll"));
        assert!(msg.contains("not found"));
    }
}
