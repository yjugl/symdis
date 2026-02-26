// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::fmt::Write;
use std::io::BufReader;

use anyhow::{Context, Result};
use serde::Serialize;
use tracing::warn;

use super::FetchArgs;
use crate::cache::Cache;
use crate::config::{Config, OutputFormat};
use crate::fetch;
use crate::symbols::breakpad::SymFileSummary;

pub async fn run(args: &FetchArgs, config: &Config) -> Result<()> {
    let cache = Cache::new(&config.cache_dir, config.miss_ttl_hours);
    let client = fetch::build_http_client(config)?;

    // Fetch .sym file and binary concurrently
    let sym_fut = fetch::fetch_sym_file(&client, &cache, config, &args.debug_file, &args.debug_id);
    let bin_fut = async {
        if let (Some(code_file), Some(code_id)) = (&args.code_file, &args.code_id) {
            fetch::fetch_binary(&client, &cache, config, code_file, code_id).await
        } else {
            let code_file = derive_code_file(&args.debug_file);
            fetch::fetch_binary(&client, &cache, config, &code_file, &args.debug_id).await
        }
    };

    let (sym_result, bin_result) = tokio::join!(sym_fut, bin_fut);

    // Quick-scan .sym file for OS/arch (needed for debuginfod/FTP fallback)
    let sym_summary = match &sym_result {
        Ok(path) => {
            let file = std::fs::File::open(path)
                .with_context(|| format!("opening sym file: {}", path.display()))?;
            let reader = BufReader::new(file);
            match SymFileSummary::scan(reader) {
                Ok(summary) => Some(summary),
                Err(e) => {
                    warn!("failed to scan sym file: {e}");
                    None
                }
            }
        }
        Err(_) => None,
    };

    // Effective code_id: prefer CLI --code-id, fall back to INFO CODE_ID from sym file.
    // This is important for debuginfod lookups where the full ELF build ID (40 chars)
    // is needed but the debug_id only preserves 32 chars (16 bytes of the GUID).
    let sym_code_id = sym_summary.as_ref().and_then(|s| s.code_id.as_deref());
    let effective_code_id = args.code_id.as_deref().or(sym_code_id);

    // If binary fetch failed and sym file indicates Linux, try debuginfod.
    // Requires a real code_id (from --code-id or INFO CODE_ID in .sym).
    let bin_result = match bin_result {
        Ok(path) => Ok(path),
        Err(e) => {
            let is_linux = sym_summary
                .as_ref()
                .map(|s| s.module.os.eq_ignore_ascii_case("linux"))
                .unwrap_or_else(|| looks_like_elf(&args.debug_file, effective_code_id));
            if is_linux {
                if let Some(code_id) = effective_code_id {
                    let code_file = args.code_file.as_deref().unwrap_or(&args.debug_file);
                    match fetch::fetch_binary_debuginfod(
                        &client, &cache, config, code_file, code_id,
                    )
                    .await
                    {
                        Ok(path) => Ok(path),
                        Err(_) => {
                            let msg = e.to_string();
                            if msg.contains("\nTried: ") {
                                Err(anyhow::anyhow!("{msg}, debuginfod"))
                            } else {
                                Err(e)
                            }
                        }
                    }
                } else {
                    Err(e)
                }
            } else {
                Err(e)
            }
        }
    };

    // If binary still not found and --snap specified, try Snap Store
    let bin_result = match bin_result {
        Ok(path) => Ok(path),
        Err(e) => {
            let is_linux = sym_summary
                .as_ref()
                .map(|s| s.module.os.eq_ignore_ascii_case("linux"))
                .unwrap_or_else(|| looks_like_elf(&args.debug_file, effective_code_id));
            if is_linux {
                if let Some(code_id) = effective_code_id {
                    if let Some(ref snap_name) = args.snap {
                        let arch = sym_summary
                            .as_ref()
                            .and_then(|s| fetch::snap::snap_architecture(&s.module.arch));
                        if let Some(arch) = arch {
                            let locator = fetch::snap::SnapLocator {
                                snap_name: snap_name.clone(),
                                architecture: arch.to_string(),
                            };
                            let archive_client = fetch::build_archive_http_client(config)?;
                            let code_file = args.code_file.as_deref().unwrap_or(&args.debug_file);
                            match fetch::fetch_binary_snap(
                                &archive_client,
                                &cache,
                                code_file,
                                code_id,
                                &locator,
                            )
                            .await
                            {
                                Ok(path) => Ok(path),
                                Err(snap_err) => {
                                    warn!("Snap Store fallback failed: {snap_err:#}");
                                    Err(e)
                                }
                            }
                        } else {
                            Err(e)
                        }
                    } else {
                        Err(e)
                    }
                } else {
                    Err(e)
                }
            } else {
                Err(e)
            }
        }
    };

    // If binary still not found and --apt specified, try APT
    let bin_result = match bin_result {
        Ok(path) => Ok(path),
        Err(e) => {
            let is_linux = sym_summary
                .as_ref()
                .map(|s| s.module.os.eq_ignore_ascii_case("linux"))
                .unwrap_or_else(|| looks_like_elf(&args.debug_file, effective_code_id));
            if is_linux && args.apt.is_some() {
                if let Some(code_id) = effective_code_id {
                    let distro = match &args.distro {
                        Some(d) => d.clone(),
                        None => {
                            warn!(
                                "--apt requires --distro (release codename, e.g., noble, bookworm)"
                            );
                            return Err(e.context("--apt requires --distro"));
                        }
                    };
                    let arch = sym_summary
                        .as_ref()
                        .and_then(|s| fetch::apt::apt_architecture(&s.module.arch));
                    if let Some(arch) = arch {
                        let apt_package = args
                            .apt
                            .as_deref()
                            .and_then(|s| if s.is_empty() { None } else { Some(s) })
                            .map(|s| s.to_string());
                        // For fetch, no auto-detection (SymFileSummary doesn't
                        // have source paths). The explicit package name goes
                        // into locator.package; source_package is None.
                        let repo_config = if let Some(ref mirror) = args.mirror {
                            fetch::apt::custom_repo_config(mirror, args.components.as_deref())
                        } else {
                            match fetch::apt::resolve_repo_config(&distro) {
                                Some(c) => c,
                                None => {
                                    warn!(
                                        "unknown release codename '{}': use --mirror to specify a custom APT repository",
                                        distro
                                    );
                                    return Err(e.context(format!(
                                        "unknown release codename '{}': use --mirror",
                                        distro
                                    )));
                                }
                            }
                        };
                        let locator = fetch::apt::AptLocator {
                            package: apt_package,
                            release: distro,
                            architecture: arch.to_string(),
                            config: repo_config,
                        };
                        let archive_client = fetch::build_archive_http_client(config)?;
                        let code_file = args.code_file.as_deref().unwrap_or(&args.debug_file);
                        match fetch::fetch_binary_apt(
                            &archive_client,
                            &cache,
                            code_file,
                            code_id,
                            &locator,
                            None,
                        )
                        .await
                        {
                            Ok(path) => Ok(path),
                            Err(apt_err) => {
                                warn!("APT fallback failed: {apt_err:#}");
                                Err(e)
                            }
                        }
                    } else {
                        Err(e)
                    }
                } else {
                    Err(e)
                }
            } else {
                Err(e)
            }
        }
    };

    // If binary still not found and --pacman specified, try pacman
    let bin_result = match bin_result {
        Ok(path) => Ok(path),
        Err(e) => {
            let is_linux = sym_summary
                .as_ref()
                .map(|s| s.module.os.eq_ignore_ascii_case("linux"))
                .unwrap_or_else(|| looks_like_elf(&args.debug_file, effective_code_id));
            if is_linux && args.pacman.is_some() {
                if let Some(code_id) = effective_code_id {
                    let arch = sym_summary
                        .as_ref()
                        .map(|s| s.module.arch.as_str())
                        .unwrap_or("x86_64");
                    let pacman_package = args
                        .pacman
                        .as_deref()
                        .and_then(|s| if s.is_empty() { None } else { Some(s) })
                        .map(|s| s.to_string());
                    match fetch::pacman::build_locator(pacman_package, args.mirror.as_deref(), arch)
                    {
                        Ok(locator) => {
                            let archive_client = fetch::build_archive_http_client(config)?;
                            let code_file = args.code_file.as_deref().unwrap_or(&args.debug_file);
                            match fetch::fetch_binary_pacman(
                                &archive_client,
                                &cache,
                                code_file,
                                code_id,
                                &locator,
                            )
                            .await
                            {
                                Ok(path) => Ok(path),
                                Err(pacman_err) => {
                                    warn!("pacman fallback failed: {pacman_err:#}");
                                    Err(e)
                                }
                            }
                        }
                        Err(locator_err) => {
                            warn!("pacman: {locator_err}");
                            Err(e)
                        }
                    }
                } else {
                    Err(e)
                }
            } else {
                Err(e)
            }
        }
    };

    // If binary still not found, try FTP archive fallback (Linux + macOS)
    let bin_result = match bin_result {
        Ok(path) => Ok(path),
        Err(e) => {
            let (os, arch_str) = sym_summary
                .as_ref()
                .map(|s| (s.module.os.as_str(), s.module.arch.as_str()))
                .unwrap_or_else(|| infer_platform_from_code_id(effective_code_id));
            if let (Some(version), Some(channel)) = (&args.version, &args.channel) {
                match fetch::archive::resolve_product_platform(&args.product, os, arch_str) {
                    Ok(Some((product, platform))) => {
                        if let Some(code_id) = effective_code_id {
                            let archive_client = fetch::build_archive_http_client(config)?;
                            let locator = fetch::archive::ArchiveLocator {
                                product,
                                version: version.clone(),
                                channel: channel.clone(),
                                platform,
                                build_id: args.build_id.clone(),
                            };
                            let code_file = args.code_file.as_deref().unwrap_or(&args.debug_file);
                            match fetch::fetch_binary_ftp(
                                &archive_client,
                                &cache,
                                config,
                                code_file,
                                code_id,
                                &locator,
                            )
                            .await
                            {
                                Ok(path) => Ok(path),
                                Err(ftp_err) => {
                                    warn!("FTP archive fallback failed: {ftp_err:#}");
                                    Err(e)
                                }
                            }
                        } else {
                            Err(e)
                        }
                    }
                    Ok(None) => Err(e),
                    Err(product_err) => {
                        warn!("product/platform resolution failed: {product_err:#}");
                        Err(e)
                    }
                }
            } else {
                Err(e)
            }
        }
    };

    // Optionally fetch PDB when --pdb is set
    let pdb_status = if args.pdb && args.debug_file.to_ascii_lowercase().ends_with(".pdb") {
        match fetch::fetch_pdb_file(&client, &cache, config, &args.debug_file, &args.debug_id).await
        {
            Ok(path) => {
                let size = std::fs::metadata(&path).map(|m| m.len()).ok();
                FileStatus::Available { size }
            }
            Err(e) => {
                warn!("PDB fetch failed: {e}");
                FileStatus::NotFound
            }
        }
    } else {
        FileStatus::Skipped
    };

    // Gather results
    let sym_status = match &sym_result {
        Ok(path) => {
            let size = std::fs::metadata(path).map(|m| m.len()).ok();
            FileStatus::Available { size }
        }
        Err(_) => FileStatus::NotFound,
    };

    let bin_status = match &bin_result {
        Ok(path) => {
            let size = std::fs::metadata(path).map(|m| m.len()).ok();
            FileStatus::Available { size }
        }
        Err(_) => FileStatus::NotFound,
    };

    let result = FetchResult {
        debug_file: args.debug_file.clone(),
        debug_id: args.debug_id.clone(),
        sym_status,
        bin_status,
        pdb_status,
    };

    match config.format {
        OutputFormat::Text => {
            let output = format_fetch_text(&result);
            print!("{output}");
        }
        OutputFormat::Json => {
            let output = format_fetch_json(&result);
            println!("{output}");
        }
    }

    Ok(())
}

/// Infer OS and architecture from code_id format when sym file is unavailable.
/// 40-char hex = ELF (Linux, guess x86_64). 32-char hex = Mach-O (macOS).
fn infer_platform_from_code_id(code_id: Option<&str>) -> (&'static str, &'static str) {
    match code_id {
        Some(id) if id.len() == 40 && id.bytes().all(|b| b.is_ascii_hexdigit()) => {
            ("Linux", "x86_64")
        }
        Some(id) if id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()) => ("mac", ""),
        _ => ("", ""),
    }
}

/// Heuristic: module looks like a Linux ELF binary.
/// Checks for `.so` in the debug file name or a 40-char hex code ID (GNU build ID).
fn looks_like_elf(debug_file: &str, code_id: Option<&str>) -> bool {
    debug_file.contains(".so")
        || code_id.is_some_and(|id| id.len() == 40 && id.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Derive a code file name from a debug file name.
/// xul.pdb -> xul.dll, ntdll.pdb -> ntdll.dll, firefox.pdb -> firefox.exe
fn derive_code_file(debug_file: &str) -> String {
    if let Some(stem) = debug_file.strip_suffix(".pdb") {
        if stem.eq_ignore_ascii_case("firefox") {
            format!("{stem}.exe")
        } else {
            format!("{stem}.dll")
        }
    } else {
        debug_file.to_string()
    }
}

enum FileStatus {
    Available { size: Option<u64> },
    NotFound,
    Skipped,
}

struct FetchResult {
    debug_file: String,
    debug_id: String,
    sym_status: FileStatus,
    bin_status: FileStatus,
    pdb_status: FileStatus,
}

// --- Text formatting ---

fn format_fetch_text(result: &FetchResult) -> String {
    let mut out = String::new();

    writeln!(out, "Fetched: {} / {}", result.debug_file, result.debug_id).unwrap();

    match &result.sym_status {
        FileStatus::Available { size: Some(size) } => {
            writeln!(out, "Symbol file: ok ({})", format_size(*size)).unwrap();
        }
        FileStatus::Available { size: None } => {
            writeln!(out, "Symbol file: ok").unwrap();
        }
        FileStatus::NotFound => {
            writeln!(out, "Symbol file: not found").unwrap();
        }
        FileStatus::Skipped => {}
    }

    match &result.bin_status {
        FileStatus::Available { size: Some(size) } => {
            writeln!(out, "Binary file: ok ({})", format_size(*size)).unwrap();
        }
        FileStatus::Available { size: None } => {
            writeln!(out, "Binary file: ok").unwrap();
        }
        FileStatus::NotFound => {
            writeln!(out, "Binary file: not found").unwrap();
        }
        FileStatus::Skipped => {}
    }

    match &result.pdb_status {
        FileStatus::Available { size: Some(size) } => {
            writeln!(out, "PDB file: ok ({})", format_size(*size)).unwrap();
        }
        FileStatus::Available { size: None } => {
            writeln!(out, "PDB file: ok").unwrap();
        }
        FileStatus::NotFound => {
            writeln!(out, "PDB file: not found").unwrap();
        }
        FileStatus::Skipped => {}
    }

    out
}

/// Format a byte size as a human-readable string.
fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

// --- JSON formatting ---

#[derive(Serialize)]
struct JsonFetchOutput {
    debug_file: String,
    debug_id: String,
    symbol_file: JsonFileStatus,
    binary_file: JsonFileStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pdb_file: Option<JsonFileStatus>,
}

#[derive(Serialize)]
struct JsonFileStatus {
    available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
}

fn format_fetch_json(result: &FetchResult) -> String {
    let file_status_to_json = |status: &FileStatus| -> JsonFileStatus {
        match status {
            FileStatus::Available { size } => JsonFileStatus {
                available: true,
                size: *size,
            },
            FileStatus::NotFound | FileStatus::Skipped => JsonFileStatus {
                available: false,
                size: None,
            },
        }
    };

    let pdb_file = match &result.pdb_status {
        FileStatus::Skipped => None,
        status => Some(file_status_to_json(status)),
    };

    let output = JsonFetchOutput {
        debug_file: result.debug_file.clone(),
        debug_id: result.debug_id.clone(),
        symbol_file: file_status_to_json(&result.sym_status),
        binary_file: file_status_to_json(&result.bin_status),
        pdb_file,
    };
    serde_json::to_string_pretty(&output).expect("JSON serialization should not fail")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_result(sym_available: bool, bin_available: bool) -> FetchResult {
        FetchResult {
            debug_file: "xul.pdb".to_string(),
            debug_id: "44E4EC8C2F41492B9369D6B9A059577C2".to_string(),
            sym_status: if sym_available {
                FileStatus::Available {
                    size: Some(432_000_000),
                }
            } else {
                FileStatus::NotFound
            },
            bin_status: if bin_available {
                FileStatus::Available {
                    size: Some(128_000_000),
                }
            } else {
                FileStatus::NotFound
            },
            pdb_status: FileStatus::Skipped,
        }
    }

    #[test]
    fn test_fetch_text_both_available() {
        let result = make_result(true, true);
        let output = format_fetch_text(&result);
        assert!(output.contains("Fetched: xul.pdb / 44E4EC8C2F41492B9369D6B9A059577C2"));
        assert!(output.contains("Symbol file: ok (412.0 MB)"));
        assert!(output.contains("Binary file: ok (122.1 MB)"));
    }

    #[test]
    fn test_fetch_text_sym_only() {
        let result = make_result(true, false);
        let output = format_fetch_text(&result);
        assert!(output.contains("Symbol file: ok (412.0 MB)"));
        assert!(output.contains("Binary file: not found"));
    }

    #[test]
    fn test_fetch_text_nothing() {
        let result = make_result(false, false);
        let output = format_fetch_text(&result);
        assert!(output.contains("Symbol file: not found"));
        assert!(output.contains("Binary file: not found"));
    }

    #[test]
    fn test_fetch_json_both_available() {
        let result = make_result(true, true);
        let json_str = format_fetch_json(&result);
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(v["debug_file"], "xul.pdb");
        assert_eq!(v["debug_id"], "44E4EC8C2F41492B9369D6B9A059577C2");
        assert!(v["symbol_file"]["available"].as_bool().unwrap());
        assert_eq!(v["symbol_file"]["size"], 432_000_000);
        assert!(v["binary_file"]["available"].as_bool().unwrap());
        assert_eq!(v["binary_file"]["size"], 128_000_000);
    }

    #[test]
    fn test_fetch_json_not_found() {
        let result = make_result(false, false);
        let json_str = format_fetch_json(&result);
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert!(!v["symbol_file"]["available"].as_bool().unwrap());
        assert!(v["symbol_file"]["size"].is_null());
        assert!(!v["binary_file"]["available"].as_bool().unwrap());
        assert!(v["binary_file"]["size"].is_null());
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1_048_576), "1.0 MB");
        assert_eq!(format_size(1_073_741_824), "1.0 GB");
    }

    #[test]
    fn test_derive_code_file() {
        assert_eq!(derive_code_file("xul.pdb"), "xul.dll");
        assert_eq!(derive_code_file("firefox.pdb"), "firefox.exe");
        assert_eq!(derive_code_file("libxul.so"), "libxul.so");
        assert_eq!(derive_code_file("XUL"), "XUL");
    }
}
