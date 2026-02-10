// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::fmt::Write;
use std::io::BufReader;

use anyhow::{Result, Context};
use tracing::warn;
use serde::Serialize;

use super::InfoArgs;
use crate::cache::Cache;
use crate::config::{Config, OutputFormat};
use crate::fetch;
use crate::symbols::breakpad::SymFileSummary;

pub async fn run(args: &InfoArgs, config: &Config) -> Result<()> {
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

    // Scan .sym file for summary (MODULE record + counts) without full parse
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

    // If binary fetch failed and sym file indicates Linux, try debuginfod
    let bin_result = match bin_result {
        Ok(path) => Ok(path),
        Err(e) => {
            let is_linux = sym_summary.as_ref()
                .map(|s| s.module.os.eq_ignore_ascii_case("linux"))
                .unwrap_or_else(|| looks_like_elf(&args.debug_file));
            if is_linux {
                let code_file = args.code_file.as_deref().unwrap_or(&args.debug_file);
                match fetch::fetch_binary_debuginfod(&client, &cache, config, code_file, args.code_id.as_deref(), &args.debug_id).await {
                    Ok(path) => Ok(path),
                    Err(_) => Err(e),
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
            let os = sym_summary.as_ref().map(|s| s.module.os.as_str()).unwrap_or("");
            let arch_str = sym_summary.as_ref().map(|s| s.module.arch.as_str()).unwrap_or("");
            if let (Some(version), Some(channel)) = (&args.version, &args.channel) {
                if let Some(platform) = fetch::archive::ftp_platform(os, arch_str) {
                    let archive_client = fetch::build_archive_http_client(config)?;
                    let locator = fetch::archive::ArchiveLocator {
                        product: args.product.clone(),
                        version: version.clone(),
                        channel: channel.clone(),
                        platform: platform.to_string(),
                        build_id: args.build_id.clone(),
                    };
                    let code_file = args.code_file.as_deref().unwrap_or(&args.debug_file);
                    match fetch::fetch_binary_ftp(&archive_client, &cache, config, code_file, args.code_id.as_deref(), &args.debug_id, &locator).await {
                        Ok(path) => Ok(path),
                        Err(ftp_err) => {
                            warn!("FTP archive fallback failed: {ftp_err}");
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

    // Gather info
    let mut info = ModuleMetadata {
        debug_file: args.debug_file.clone(),
        debug_id: args.debug_id.clone(),
        code_file: args.code_file.clone(),
        code_id: args.code_id.clone(),
        os: None,
        arch: None,
        sym_status: FileStatus::NotFound,
        binary_status: FileStatus::NotFound,
        function_count: None,
        public_count: None,
    };

    // Fill in from .sym file summary
    if let Some(ref summary) = sym_summary {
        info.os = Some(summary.module.os.clone());
        info.arch = Some(summary.module.arch.clone());
        info.function_count = Some(summary.function_count);
        info.public_count = Some(summary.public_count);
    }

    // Sym file status
    match &sym_result {
        Ok(path) => {
            let size = std::fs::metadata(path).map(|m| m.len()).ok();
            info.sym_status = FileStatus::Available { size };
        }
        Err(_) => {
            info.sym_status = FileStatus::NotFound;
        }
    }

    // Binary status
    match &bin_result {
        Ok(path) => {
            let size = std::fs::metadata(path).map(|m| m.len()).ok();
            info.binary_status = FileStatus::Available { size };
        }
        Err(_) => {
            info.binary_status = FileStatus::NotFound;
        }
    }

    match config.format {
        OutputFormat::Text => {
            let output = format_info_text(&info);
            print!("{output}");
        }
        OutputFormat::Json => {
            let output = format_info_json(&info);
            println!("{output}");
        }
    }

    Ok(())
}

/// Heuristic: debug file name looks like a Linux ELF shared library.
/// Used to try debuginfod when the sym file is unavailable.
fn looks_like_elf(debug_file: &str) -> bool {
    debug_file.contains(".so")
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
}

struct ModuleMetadata {
    debug_file: String,
    debug_id: String,
    code_file: Option<String>,
    code_id: Option<String>,
    os: Option<String>,
    arch: Option<String>,
    sym_status: FileStatus,
    binary_status: FileStatus,
    function_count: Option<usize>,
    public_count: Option<usize>,
}

// --- Text formatting ---

fn format_info_text(info: &ModuleMetadata) -> String {
    let mut out = String::new();

    let module_name = info.code_file.as_deref().unwrap_or(&info.debug_file);
    writeln!(out, "Module: {}", module_name).unwrap();
    writeln!(out, "Debug file: {}", info.debug_file).unwrap();
    writeln!(out, "Debug ID: {}", info.debug_id).unwrap();
    if let Some(ref code_file) = info.code_file {
        writeln!(out, "Code file: {}", code_file).unwrap();
    }
    if let Some(ref code_id) = info.code_id {
        writeln!(out, "Code ID: {}", code_id).unwrap();
    }
    if let Some(ref os) = info.os {
        writeln!(out, "OS: {}", os).unwrap();
    }
    if let Some(ref arch) = info.arch {
        writeln!(out, "Architecture: {}", arch).unwrap();
    }

    match &info.sym_status {
        FileStatus::Available { size: Some(size) } => {
            writeln!(out, "Symbol file: available ({})", format_size(*size)).unwrap();
        }
        FileStatus::Available { size: None } => {
            writeln!(out, "Symbol file: available").unwrap();
        }
        FileStatus::NotFound => {
            writeln!(out, "Symbol file: not found").unwrap();
        }
    }

    match &info.binary_status {
        FileStatus::Available { size: Some(size) } => {
            writeln!(out, "Binary file: available ({})", format_size(*size)).unwrap();
        }
        FileStatus::Available { size: None } => {
            writeln!(out, "Binary file: available").unwrap();
        }
        FileStatus::NotFound => {
            writeln!(out, "Binary file: not found").unwrap();
        }
    }

    if let Some(count) = info.function_count {
        writeln!(out, "Functions: {}", format_count(count)).unwrap();
    }
    if let Some(count) = info.public_count {
        writeln!(out, "PUBLIC symbols: {}", format_count(count)).unwrap();
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

/// Format a count with thousands separators.
fn format_count(n: usize) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

// --- JSON formatting ---

#[derive(Serialize)]
struct JsonInfoOutput {
    debug_file: String,
    debug_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    code_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    arch: Option<String>,
    symbol_file: JsonFileStatus,
    binary_file: JsonFileStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    function_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_count: Option<usize>,
}

#[derive(Serialize)]
struct JsonFileStatus {
    available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
}

fn format_info_json(info: &ModuleMetadata) -> String {
    let output = JsonInfoOutput {
        debug_file: info.debug_file.clone(),
        debug_id: info.debug_id.clone(),
        code_file: info.code_file.clone(),
        code_id: info.code_id.clone(),
        os: info.os.clone(),
        arch: info.arch.clone(),
        symbol_file: match &info.sym_status {
            FileStatus::Available { size } => JsonFileStatus {
                available: true,
                size: *size,
            },
            FileStatus::NotFound => JsonFileStatus {
                available: false,
                size: None,
            },
        },
        binary_file: match &info.binary_status {
            FileStatus::Available { size } => JsonFileStatus {
                available: true,
                size: *size,
            },
            FileStatus::NotFound => JsonFileStatus {
                available: false,
                size: None,
            },
        },
        function_count: info.function_count,
        public_count: info.public_count,
    };
    serde_json::to_string_pretty(&output).expect("JSON serialization should not fail")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_metadata(sym_available: bool, bin_available: bool) -> ModuleMetadata {
        ModuleMetadata {
            debug_file: "test.pdb".to_string(),
            debug_id: "AABBCCDD11223344".to_string(),
            code_file: Some("test.dll".to_string()),
            code_id: Some("5CF2591C6859000".to_string()),
            os: Some("windows".to_string()),
            arch: Some("x86_64".to_string()),
            sym_status: if sym_available {
                FileStatus::Available { size: Some(432_000_000) }
            } else {
                FileStatus::NotFound
            },
            binary_status: if bin_available {
                FileStatus::Available { size: Some(128_000_000) }
            } else {
                FileStatus::NotFound
            },
            function_count: if sym_available { Some(284301) } else { None },
            public_count: if sym_available { Some(12445) } else { None },
        }
    }

    #[test]
    fn test_info_text_full() {
        let info = make_metadata(true, true);
        let output = format_info_text(&info);
        assert!(output.contains("Module: test.dll"));
        assert!(output.contains("Debug file: test.pdb"));
        assert!(output.contains("Debug ID: AABBCCDD11223344"));
        assert!(output.contains("Code file: test.dll"));
        assert!(output.contains("Code ID: 5CF2591C6859000"));
        assert!(output.contains("OS: windows"));
        assert!(output.contains("Architecture: x86_64"));
        assert!(output.contains("Symbol file: available (412.0 MB)"));
        assert!(output.contains("Binary file: available (122.1 MB)"));
        assert!(output.contains("Functions: 284,301"));
        assert!(output.contains("PUBLIC symbols: 12,445"));
    }

    #[test]
    fn test_info_text_sym_only() {
        let info = make_metadata(true, false);
        let output = format_info_text(&info);
        assert!(output.contains("Symbol file: available"));
        assert!(output.contains("Binary file: not found"));
    }

    #[test]
    fn test_info_text_nothing() {
        let info = make_metadata(false, false);
        let output = format_info_text(&info);
        assert!(output.contains("Symbol file: not found"));
        assert!(output.contains("Binary file: not found"));
        assert!(!output.contains("Functions:"));
    }

    #[test]
    fn test_info_json_full() {
        let info = make_metadata(true, true);
        let json_str = format_info_json(&info);
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(v["debug_file"], "test.pdb");
        assert_eq!(v["debug_id"], "AABBCCDD11223344");
        assert_eq!(v["code_file"], "test.dll");
        assert_eq!(v["os"], "windows");
        assert_eq!(v["arch"], "x86_64");
        assert!(v["symbol_file"]["available"].as_bool().unwrap());
        assert_eq!(v["symbol_file"]["size"], 432_000_000);
        assert!(v["binary_file"]["available"].as_bool().unwrap());
        assert_eq!(v["function_count"], 284301);
        assert_eq!(v["public_count"], 12445);
    }

    #[test]
    fn test_info_json_not_found() {
        let info = make_metadata(false, false);
        let json_str = format_info_json(&info);
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert!(!v["symbol_file"]["available"].as_bool().unwrap());
        assert!(v["symbol_file"]["size"].is_null());
        assert!(!v["binary_file"]["available"].as_bool().unwrap());
        assert!(v["function_count"].is_null());
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1536), "1.5 KB");
        assert_eq!(format_size(1_048_576), "1.0 MB");
        assert_eq!(format_size(1_073_741_824), "1.0 GB");
    }

    #[test]
    fn test_format_count() {
        assert_eq!(format_count(0), "0");
        assert_eq!(format_count(42), "42");
        assert_eq!(format_count(999), "999");
        assert_eq!(format_count(1000), "1,000");
        assert_eq!(format_count(12445), "12,445");
        assert_eq!(format_count(284301), "284,301");
        assert_eq!(format_count(1000000), "1,000,000");
    }

    #[test]
    fn test_derive_code_file() {
        assert_eq!(derive_code_file("xul.pdb"), "xul.dll");
        assert_eq!(derive_code_file("ntdll.pdb"), "ntdll.dll");
        assert_eq!(derive_code_file("firefox.pdb"), "firefox.exe");
        assert_eq!(derive_code_file("Firefox.pdb"), "Firefox.exe");
        assert_eq!(derive_code_file("libxul.so"), "libxul.so");
        assert_eq!(derive_code_file("XUL"), "XUL");
    }
}
