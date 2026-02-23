// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::commands::{Cli, Command, FormatArg, SyntaxArg};

// --- TOML file structs (all fields Option for partial configs) ---

#[derive(Deserialize, Default)]
struct ConfigFile {
    cache: Option<CacheSection>,
    symbols: Option<SymbolsSection>,
    disassembly: Option<DisassemblySection>,
    output: Option<OutputSection>,
    network: Option<NetworkSection>,
}

#[derive(Deserialize, Default)]
struct CacheSection {
    dir: Option<String>,
    miss_ttl_hours: Option<u64>,
}

#[derive(Deserialize, Default)]
struct SymbolsSection {
    servers: Option<Vec<String>>,
    debuginfod_urls: Option<Vec<String>>,
}

#[derive(Deserialize, Default)]
struct DisassemblySection {
    syntax: Option<String>,
    max_instructions: Option<usize>,
}

#[derive(Deserialize, Default)]
struct OutputSection {
    format: Option<String>,
}

#[derive(Deserialize, Default)]
struct NetworkSection {
    timeout_seconds: Option<u64>,
    archive_timeout_seconds: Option<u64>,
    user_agent: Option<String>,
    offline: Option<bool>,
}

// --- Resolved config ---

pub struct Config {
    pub cache_dir: PathBuf,
    pub miss_ttl_hours: u64,
    pub symbol_servers: Vec<String>,
    pub debuginfod_urls: Vec<String>,
    pub timeout_seconds: u64,
    pub archive_timeout_seconds: u64,
    pub user_agent: String,
    pub syntax: Syntax,
    pub max_instructions: usize,
    pub format: OutputFormat,
    pub no_demangle: bool,
    pub offline: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Syntax {
    Intel,
    Att,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            cache_dir: PathBuf::new(), // placeholder; resolved later
            miss_ttl_hours: 24,
            symbol_servers: vec![
                "https://symbols.mozilla.org/".to_string(),
                "https://msdl.microsoft.com/download/symbols".to_string(),
            ],
            debuginfod_urls: vec![
                "https://debuginfod.fedoraproject.org/".to_string(),
                "https://debuginfod.ubuntu.com/".to_string(),
                "https://debuginfod.debian.net/".to_string(),
                "https://debuginfod.archlinux.org/".to_string(),
                "https://debuginfod.elfutils.org/".to_string(),
                "https://debuginfod.centos.org/".to_string(),
            ],
            timeout_seconds: 30,
            archive_timeout_seconds: 600,
            user_agent: format!("symdis/{}", env!("CARGO_PKG_VERSION")),
            syntax: Syntax::Intel,
            max_instructions: 2000,
            format: OutputFormat::Text,
            no_demangle: false,
            offline: false,
        }
    }
}

impl Config {
    /// Resolve configuration by merging: defaults < config file < env vars < CLI flags.
    pub fn resolve(cli: &Cli) -> Result<Config> {
        let mut config = Config::default();

        // --- Layer 2: config file ---
        let config_path = config_file_path_override().or_else(config_file_path_default);

        if let Some(path) = config_path {
            if path.exists() {
                let contents = std::fs::read_to_string(&path)
                    .with_context(|| format!("reading config file: {}", path.display()))?;
                let file: ConfigFile = toml::from_str(&contents)
                    .with_context(|| format!("parsing config file: {}", path.display()))?;
                apply_config_file(&mut config, &file);
            }
        }

        // --- Layer 3: environment variables ---
        apply_env_vars(&mut config);

        // --- Layer 4: CLI flags ---
        apply_cli(&mut config, cli);

        // --- Resolve cache_dir if not yet set ---
        if config.cache_dir.as_os_str().is_empty() {
            config.cache_dir = resolve_cache_dir()?;
        }

        Ok(config)
    }
}

/// Apply non-None fields from TOML config file onto config.
fn apply_config_file(config: &mut Config, file: &ConfigFile) {
    if let Some(ref cache) = file.cache {
        if let Some(ref dir) = cache.dir {
            config.cache_dir = PathBuf::from(dir);
        }
        if let Some(ttl) = cache.miss_ttl_hours {
            config.miss_ttl_hours = ttl;
        }
    }
    if let Some(ref symbols) = file.symbols {
        if let Some(ref servers) = symbols.servers {
            config.symbol_servers = servers.clone();
        }
        if let Some(ref urls) = symbols.debuginfod_urls {
            config.debuginfod_urls = urls.clone();
        }
    }
    if let Some(ref disasm) = file.disassembly {
        if let Some(ref syntax) = disasm.syntax {
            match syntax.to_ascii_lowercase().as_str() {
                "intel" => config.syntax = Syntax::Intel,
                "att" => config.syntax = Syntax::Att,
                _ => {} // ignore unknown values
            }
        }
        if let Some(max) = disasm.max_instructions {
            config.max_instructions = max;
        }
    }
    if let Some(ref output) = file.output {
        if let Some(ref fmt) = output.format {
            match fmt.to_ascii_lowercase().as_str() {
                "text" => config.format = OutputFormat::Text,
                "json" => config.format = OutputFormat::Json,
                _ => {}
            }
        }
    }
    if let Some(ref network) = file.network {
        if let Some(timeout) = network.timeout_seconds {
            config.timeout_seconds = timeout;
        }
        if let Some(timeout) = network.archive_timeout_seconds {
            config.archive_timeout_seconds = timeout;
        }
        if let Some(ref ua) = network.user_agent {
            config.user_agent = ua.clone();
        }
        if let Some(offline) = network.offline {
            config.offline = offline;
        }
    }
}

/// Apply environment variable overrides.
fn apply_env_vars(config: &mut Config) {
    if let Ok(val) = std::env::var("SYMDIS_SYMBOL_SERVERS") {
        let servers: Vec<String> = val
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !servers.is_empty() {
            config.symbol_servers = servers;
        }
    }

    if let Ok(val) = std::env::var("DEBUGINFOD_URLS") {
        let urls: Vec<String> = val
            .split_whitespace()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        if !urls.is_empty() {
            config.debuginfod_urls = urls;
        }
    }

    if let Ok(val) = std::env::var("SYMDIS_CACHE_DIR") {
        if !val.is_empty() {
            config.cache_dir = PathBuf::from(val);
        }
    }
}

/// Apply CLI flag overrides.
fn apply_cli(config: &mut Config, cli: &Cli) {
    if let Some(ref dir) = cli.cache_dir {
        config.cache_dir = PathBuf::from(dir);
    }

    match cli.format {
        FormatArg::Text => config.format = OutputFormat::Text,
        FormatArg::Json => config.format = OutputFormat::Json,
    }

    if cli.no_demangle {
        config.no_demangle = true;
    }

    if cli.offline {
        config.offline = true;
    }

    // Subcommand-specific overrides
    if let Command::Disasm(ref args) = cli.command {
        match args.syntax {
            SyntaxArg::Intel => config.syntax = Syntax::Intel,
            SyntaxArg::Att => config.syntax = Syntax::Att,
        }
        config.max_instructions = args.max_instructions;
    }
}

/// Get config file path from SYMDIS_CONFIG env var.
fn config_file_path_override() -> Option<PathBuf> {
    std::env::var("SYMDIS_CONFIG")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

/// Get platform-specific default config file path.
fn config_file_path_default() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("symdis").join("config.toml"))
}

/// Resolve cache directory from env vars and platform defaults.
/// Called when no explicit cache_dir was set by config file, env var, or CLI.
fn resolve_cache_dir() -> Result<PathBuf> {
    // Check _NT_SYMBOL_PATH on Windows
    if let Ok(sym_path) = std::env::var("_NT_SYMBOL_PATH") {
        if let Some(cache_dir) = parse_nt_symbol_path(&sym_path) {
            return Ok(cache_dir);
        }
    }

    // Platform default
    if let Some(cache_dir) = dirs::cache_dir() {
        return Ok(cache_dir.join("symdis"));
    }

    // Fallback
    Ok(PathBuf::from(".symdis-cache"))
}

/// Parse `_NT_SYMBOL_PATH` to extract the first local cache directory.
///
/// Recognized forms (case-insensitive prefixes):
///   `srv*<local_cache>*<server>`  — local_cache is a downstream store
///   `srv*<server>`                — no local cache, skip
///   `cache*<dir>;...`            — dir is used to cache anything to the right
///   `cache*;...`                 — default cache location, not useful to us
///   `symsrv*symsrv.dll*<cache>*<server>` — older verbose form, same idea
///
/// See: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/symbol-path
pub fn parse_nt_symbol_path(sym_path: &str) -> Option<PathBuf> {
    for entry in sym_path.split(';') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }

        let entry_lower = entry.to_ascii_lowercase();

        // Handle cache*<dir> — "cache everything to the right into <dir>"
        if let Some(rest) = entry_lower.strip_prefix("cache*") {
            if !rest.is_empty() {
                // Extract the original-case dir (skip "cache*" prefix = 6 chars)
                let dir = &entry[6..];
                if is_local_path(dir) {
                    return Some(PathBuf::from(dir));
                }
            }
            // cache* with no dir — WinDbg defaults to C:\ProgramData\Dbg\sym
            let default = PathBuf::from(r"C:\ProgramData\Dbg\sym");
            if default.is_dir() {
                return Some(default);
            }
            continue;
        }

        // Handle srv*<cache>*<server> or symsrv*symsrv.dll*<cache>*<server>
        let rest = if entry_lower.strip_prefix("srv*").is_some() {
            // rest starts after "srv*" — use original case
            Some(&entry[4..])
        } else if entry_lower.strip_prefix("symsrv*").is_some() {
            // symsrv*symsrv.dll*<cache>*<server> — skip the DLL name
            let original_rest = &entry[7..];
            original_rest
                .split_once('*')
                .map(|(_, after_dll)| after_dll)
        } else {
            None
        };

        if let Some(rest) = rest {
            let parts: Vec<&str> = rest.split('*').collect();
            // Need at least 2 parts (cache*server) and first must be a local path
            if parts.len() >= 2 && !parts[0].is_empty() && is_local_path(parts[0]) {
                return Some(PathBuf::from(parts[0]));
            }
        }
    }
    None
}

/// Check that a string looks like a local filesystem path, not a URL.
fn is_local_path(s: &str) -> bool {
    !s.starts_with("http://")
        && !s.starts_with("https://")
        && !s.starts_with("HTTP://")
        && !s.starts_with("HTTPS://")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.timeout_seconds, 30);
        assert_eq!(config.archive_timeout_seconds, 600);
        assert_eq!(config.miss_ttl_hours, 24);
        assert_eq!(config.syntax, Syntax::Intel);
        assert_eq!(config.max_instructions, 2000);
        assert_eq!(config.format, OutputFormat::Text);
        assert!(!config.no_demangle);
        assert!(!config.offline);
        assert_eq!(config.symbol_servers.len(), 2);
        assert_eq!(config.debuginfod_urls.len(), 6);
        assert!(config.user_agent.starts_with("symdis/"));
    }

    #[test]
    fn test_toml_parse_full() {
        let toml_str = r#"
[cache]
dir = "/tmp/symdis-cache"
miss_ttl_hours = 48

[symbols]
servers = ["https://example.com/symbols"]
debuginfod_urls = ["https://debuginfod.example.com"]

[disassembly]
syntax = "att"
max_instructions = 5000

[output]
format = "json"

[network]
timeout_seconds = 60
user_agent = "custom-agent/1.0"
"#;
        let file: ConfigFile = toml::from_str(toml_str).unwrap();
        let mut config = Config::default();
        apply_config_file(&mut config, &file);

        assert_eq!(config.cache_dir, PathBuf::from("/tmp/symdis-cache"));
        assert_eq!(config.miss_ttl_hours, 48);
        assert_eq!(config.symbol_servers, vec!["https://example.com/symbols"]);
        assert_eq!(
            config.debuginfod_urls,
            vec!["https://debuginfod.example.com"]
        );
        assert_eq!(config.syntax, Syntax::Att);
        assert_eq!(config.max_instructions, 5000);
        assert_eq!(config.format, OutputFormat::Json);
        assert_eq!(config.timeout_seconds, 60);
        assert_eq!(config.user_agent, "custom-agent/1.0");
    }

    #[test]
    fn test_toml_parse_partial() {
        let toml_str = r#"
[network]
timeout_seconds = 120
"#;
        let file: ConfigFile = toml::from_str(toml_str).unwrap();
        let mut config = Config::default();
        apply_config_file(&mut config, &file);

        // Only timeout changed, everything else stays default
        assert_eq!(config.timeout_seconds, 120);
        assert_eq!(config.syntax, Syntax::Intel);
        assert_eq!(config.max_instructions, 2000);
        assert_eq!(config.symbol_servers.len(), 2);
    }

    #[test]
    fn test_toml_parse_empty() {
        let file: ConfigFile = toml::from_str("").unwrap();
        let mut config = Config::default();
        apply_config_file(&mut config, &file);

        // Nothing changed
        assert_eq!(config.timeout_seconds, 30);
        assert_eq!(config.syntax, Syntax::Intel);
    }

    #[test]
    fn test_toml_parse_invalid() {
        let result: Result<ConfigFile, _> = toml::from_str("this is not valid toml [[[");
        assert!(result.is_err());
    }

    #[test]
    fn test_config_file_path_default() {
        // Just verify the function returns something (platform-dependent)
        let path = config_file_path_default();
        if let Some(p) = path {
            assert!(p.ends_with("config.toml"));
        }
    }

    // --- _NT_SYMBOL_PATH tests (moved from cache.rs) ---

    #[test]
    fn test_srv_with_cache_and_server() {
        let path =
            parse_nt_symbol_path("SRV*C:\\Symbols*https://msdl.microsoft.com/download/symbols");
        assert_eq!(path, Some(PathBuf::from("C:\\Symbols")));
    }

    #[test]
    fn test_srv_chained() {
        let path =
            parse_nt_symbol_path("SRV*C:\\Sym1*https://server1;SRV*C:\\Sym2*https://server2");
        assert_eq!(path, Some(PathBuf::from("C:\\Sym1")));
    }

    #[test]
    fn test_srv_lowercase() {
        let path = parse_nt_symbol_path("srv*D:\\MySymbols*https://server");
        assert_eq!(path, Some(PathBuf::from("D:\\MySymbols")));
    }

    #[test]
    fn test_srv_mixed_case() {
        let path = parse_nt_symbol_path("Srv*E:\\Syms*https://server");
        assert_eq!(path, Some(PathBuf::from("E:\\Syms")));
    }

    #[test]
    fn test_srv_server_only_no_cache() {
        assert_eq!(
            parse_nt_symbol_path("srv*https://msdl.microsoft.com/download/symbols"),
            None,
        );
    }

    #[test]
    fn test_srv_server_only_skipped_then_cache_found() {
        let path = parse_nt_symbol_path("SRV*https://server1;SRV*C:\\Symbols*https://server2");
        assert_eq!(path, Some(PathBuf::from("C:\\Symbols")));
    }

    #[test]
    fn test_cache_with_dir() {
        let path = parse_nt_symbol_path(
            "cache*C:\\MySymbols;srv*https://msdl.microsoft.com/download/symbols",
        );
        assert_eq!(path, Some(PathBuf::from("C:\\MySymbols")));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_cache_no_dir_default() {
        let path = parse_nt_symbol_path("cache*;srv*https://msdl.microsoft.com/download/symbols");
        let windbg_default = std::path::Path::new(r"C:\ProgramData\Dbg\sym");
        if windbg_default.is_dir() {
            assert_eq!(path, Some(windbg_default.to_path_buf()));
        } else {
            assert_eq!(path, None);
        }
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_cache_no_dir_falls_through_to_srv() {
        let path = parse_nt_symbol_path(
            "cache*;srv*C:\\ServerCache*https://msdl.microsoft.com/download/symbols",
        );
        let windbg_default = std::path::Path::new(r"C:\ProgramData\Dbg\sym");
        if windbg_default.is_dir() {
            assert_eq!(path, Some(windbg_default.to_path_buf()));
        } else {
            assert_eq!(path, Some(PathBuf::from("C:\\ServerCache")));
        }
    }

    #[test]
    fn test_cache_mixed_case() {
        let path = parse_nt_symbol_path("CACHE*D:\\SymCache;srv*https://server");
        assert_eq!(path, Some(PathBuf::from("D:\\SymCache")));
    }

    #[test]
    fn test_symsrv_with_dll_cache_server() {
        let path = parse_nt_symbol_path(
            "symsrv*symsrv.dll*C:\\Symbols*https://msdl.microsoft.com/download/symbols",
        );
        assert_eq!(path, Some(PathBuf::from("C:\\Symbols")));
    }

    #[test]
    fn test_symsrv_no_cache() {
        assert_eq!(
            parse_nt_symbol_path("symsrv*symsrv.dll*https://msdl.microsoft.com"),
            None,
        );
    }

    #[test]
    fn test_empty_string() {
        assert_eq!(parse_nt_symbol_path(""), None);
    }

    #[test]
    fn test_plain_local_path_ignored() {
        assert_eq!(parse_nt_symbol_path("C:\\JustAPath"), None);
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_real_world_no_explicit_cache() {
        let path = parse_nt_symbol_path(
            "cache*;srv*https://msdl.microsoft.com/download/symbols;srv*https://symbols.mozilla.org/try",
        );
        let windbg_default = std::path::Path::new(r"C:\ProgramData\Dbg\sym");
        if windbg_default.is_dir() {
            assert_eq!(path, Some(windbg_default.to_path_buf()));
        } else {
            assert_eq!(path, None);
        }
    }

    #[test]
    fn test_network_share_as_cache() {
        let path = parse_nt_symbol_path("srv*\\\\server\\share*https://msdl.microsoft.com");
        assert_eq!(path, Some(PathBuf::from("\\\\server\\share")));
    }
}
