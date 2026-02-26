// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

pub mod apt;
pub mod archive;
pub mod debuginfod;
pub mod microsoft;
pub mod snap;
pub mod tecken;

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use reqwest::Client;
use tracing::{debug, info, warn};

use std::io::Read;

use crate::cache::{BinaryCacheKey, Cache, CacheResult, PdbCacheKey, SymbolCacheKey};
use crate::config::Config;

/// Result of a fetch attempt.
pub enum FetchResult {
    /// Successfully fetched, data is the file contents.
    Ok(Vec<u8>),
    /// Server returned 404.
    NotFound,
    /// Network or server error.
    Error(String),
}

/// Create a shared HTTP client with standard configuration.
pub fn build_http_client(config: &Config) -> Result<Client> {
    Client::builder()
        .user_agent(&config.user_agent)
        .timeout(std::time::Duration::from_secs(config.timeout_seconds))
        .redirect(reqwest::redirect::Policy::limited(10))
        .gzip(true)
        .build()
        .context("building HTTP client")
}

/// Derive the .sym filename from a debug file name.
/// xul.pdb -> xul.sym, libxul.so -> libxul.so.sym, XUL -> XUL.sym
pub fn sym_filename(debug_file: &str) -> String {
    if let Some(stem) = debug_file.strip_suffix(".pdb") {
        format!("{stem}.sym")
    } else {
        format!("{debug_file}.sym")
    }
}

/// Fetch a .sym file, checking cache first, then trying symbol servers.
pub async fn fetch_sym_file(
    client: &Client,
    cache: &Cache,
    config: &Config,
    debug_file: &str,
    debug_id: &str,
) -> Result<PathBuf> {
    let sym_name = sym_filename(debug_file);
    let key = SymbolCacheKey {
        debug_file: debug_file.to_string(),
        debug_id: debug_id.to_string(),
        filename: sym_name.clone(),
    };

    // Check cache
    match cache.get_sym(&key) {
        CacheResult::Hit(path) => {
            info!("cache hit: {debug_file}/{debug_id}/{sym_name}");
            return Ok(path);
        }
        CacheResult::NegativeHit => {
            debug!("negative cache hit: {debug_file}/{debug_id}/{sym_name}");
            bail!("symbol file not available (cached negative result)");
        }
        CacheResult::Miss => {
            debug!("cache miss: {debug_file}/{debug_id}/{sym_name}");
        }
    }

    if config.offline {
        bail!("symbol file not in cache and --offline is set: {debug_file}/{debug_id}/{sym_name}");
    }

    // Try Tecken (first symbol server)
    let tecken_url = config
        .symbol_servers
        .first()
        .map(|s| s.as_str())
        .unwrap_or(tecken::DEFAULT_TECKEN_BASE);

    match tecken::fetch_sym(client, tecken_url, debug_file, debug_id).await {
        FetchResult::Ok(data) => {
            if is_html_response(&data) {
                warn!("Tecken returned HTML instead of sym file for {debug_file}/{debug_id}");
            } else {
                let path = cache.store_sym(&key, &data)?;
                return Ok(path);
            }
        }
        FetchResult::NotFound => {}
        FetchResult::Error(e) => {
            warn!("Tecken fetch error: {e}");
        }
    }

    // Store miss marker
    cache.store_sym_miss(&key)?;
    bail!(
        "symbol file not found: {debug_file}/{debug_id}/{sym_name}\n\
         Tried: Mozilla Tecken"
    )
}

/// Fetch a PDB file, checking cache first, then trying Tecken and symbol servers.
/// Only applicable when debug_file ends in .pdb.
///
/// Uses an extended timeout (archive_timeout_seconds) because PDB files can
/// be very large (e.g. xul.pdb ~2GB).
///
/// Fetch chain: Tecken (index 0) → all remaining symbol servers (indices 1..),
/// which use the same symsrv protocol as Microsoft's symbol server. This covers
/// Microsoft, Intel, AMD, NVIDIA, and any user-configured vendor servers.
pub async fn fetch_pdb_file(
    _client: &Client,
    cache: &Cache,
    config: &Config,
    debug_file: &str,
    debug_id: &str,
) -> Result<PathBuf> {
    let key = PdbCacheKey {
        debug_file: debug_file.to_string(),
        debug_id: debug_id.to_string(),
    };

    // Check cache
    match cache.get_pdb(&key) {
        CacheResult::Hit(path) => {
            info!("PDB cache hit: {debug_file}/{debug_id}");
            return Ok(path);
        }
        CacheResult::NegativeHit => {
            debug!("PDB negative cache hit: {debug_file}/{debug_id}");
            bail!("PDB file not available (cached negative result)");
        }
        CacheResult::Miss => {
            debug!("PDB cache miss: {debug_file}/{debug_id}");
        }
    }

    if config.offline {
        bail!("PDB file not in cache and --offline is set: {debug_file}/{debug_id}");
    }

    // PDB files can be very large (xul.pdb ~2GB), so use the extended timeout.
    // The standard `client` has a 30s timeout which is insufficient.
    let pdb_client = build_archive_http_client(config)?;

    let mut tried = Vec::new();

    // Try Tecken first (has PDBs for Mozilla modules AND Microsoft modules it has processed)
    let tecken_url = config
        .symbol_servers
        .first()
        .map(|s| s.as_str())
        .unwrap_or(tecken::DEFAULT_TECKEN_BASE);

    tried.push(server_display_name(tecken_url));

    match tecken::fetch_pdb(&pdb_client, tecken_url, debug_file, debug_id).await {
        FetchResult::Ok(data) => {
            if is_html_response(&data) {
                warn!("Tecken returned HTML instead of PDB for {debug_file}/{debug_id}");
            } else {
                let path = cache.store_pdb(&key, &data)?;
                return Ok(path);
            }
        }
        FetchResult::NotFound => {}
        FetchResult::Error(e) => {
            warn!("{} PDB fetch error: {e}", tried.last().unwrap());
        }
    }

    // Try all remaining symbol servers (same symsrv protocol: name/id/name)
    for server_url in config.symbol_servers.iter().skip(1) {
        let name = server_display_name(server_url);
        tried.push(name.clone());

        match microsoft::fetch_pdb(&pdb_client, server_url, debug_file, debug_id).await {
            FetchResult::Ok(data) => {
                if is_html_response(&data) {
                    warn!("{name} returned HTML instead of PDB for {debug_file}/{debug_id}");
                } else {
                    let path = cache.store_pdb(&key, &data)?;
                    return Ok(path);
                }
            }
            FetchResult::NotFound => {}
            FetchResult::Error(e) => {
                warn!("{name} PDB fetch error: {e}");
            }
        }
    }

    // Store miss marker
    cache.store_pdb_miss(&key)?;
    bail!(
        "PDB file not found: {debug_file}/{debug_id}\n\
         Tried: {}",
        tried.join(", ")
    )
}

/// Map a symbol server URL to a human-readable display name for error messages.
fn server_display_name(url: &str) -> String {
    if url.contains("symbols.mozilla.org") {
        "Mozilla Tecken".to_string()
    } else if url.contains("msdl.microsoft.com") {
        "Microsoft Symbol Server".to_string()
    } else if url.contains("intel.com") {
        "Intel Symbol Server".to_string()
    } else if url.contains("amd.com") {
        "AMD Symbol Server".to_string()
    } else if url.contains("nvidia.com") {
        "NVIDIA Symbol Server".to_string()
    } else {
        url.to_string()
    }
}

/// Fetch a native binary, checking cache first, then trying symbol servers.
pub async fn fetch_binary(
    client: &Client,
    cache: &Cache,
    config: &Config,
    code_file: &str,
    code_id: &str,
) -> Result<PathBuf> {
    let key = BinaryCacheKey {
        code_file: code_file.to_string(),
        code_id: code_id.to_string(),
        filename: code_file.to_string(),
    };

    // Check cache
    match cache.get_binary(&key) {
        CacheResult::Hit(path) => {
            info!("cache hit: {code_file}/{code_id}");
            return Ok(path);
        }
        CacheResult::NegativeHit => {
            debug!("negative cache hit: {code_file}/{code_id}");
            bail!("binary not available (cached negative result)");
        }
        CacheResult::Miss => {
            debug!("cache miss: {code_file}/{code_id}");
        }
    }

    if config.offline {
        bail!("binary not in cache and --offline is set: {code_file}/{code_id}");
    }

    // Try Tecken (code-file/code-id lookup)
    let tecken_url = config
        .symbol_servers
        .first()
        .map(|s| s.as_str())
        .unwrap_or(tecken::DEFAULT_TECKEN_BASE);

    match tecken::fetch_binary_by_code_id(client, tecken_url, code_file, code_id).await {
        FetchResult::Ok(data) => {
            if is_html_response(&data) {
                warn!("Tecken returned HTML instead of binary for {code_file}/{code_id}");
            } else {
                let path = cache.store_binary(&key, &data)?;
                return Ok(path);
            }
        }
        FetchResult::NotFound => {}
        FetchResult::Error(e) => {
            warn!("Tecken binary fetch error: {e}");
        }
    }

    // Try Microsoft Symbol Server (only for Windows binaries)
    if looks_like_windows_binary(code_file) {
        let ms_url = config
            .symbol_servers
            .get(1)
            .map(|s| s.as_str())
            .unwrap_or(microsoft::DEFAULT_MS_SYMBOL_SERVER);

        match microsoft::fetch_pe(client, ms_url, code_file, code_id).await {
            FetchResult::Ok(data) => {
                if is_html_response(&data) {
                    warn!("Microsoft returned HTML instead of binary for {code_file}/{code_id}");
                } else {
                    let path = cache.store_binary(&key, &data)?;
                    return Ok(path);
                }
            }
            FetchResult::NotFound => {}
            FetchResult::Error(e) => {
                warn!("Microsoft symbol server fetch error: {e}");
            }
        }
    }

    // Store miss marker
    cache.store_binary_miss(&key)?;
    if looks_like_windows_binary(code_file) {
        bail!(
            "binary not found: {code_file}/{code_id}\n\
             Tried: Mozilla Tecken, Microsoft Symbol Server"
        )
    } else {
        bail!(
            "binary not found: {code_file}/{code_id}\n\
             Tried: Mozilla Tecken"
        )
    }
}

/// Fetch a Linux binary via debuginfod, checking cache first.
///
/// The `code_id` is used directly as the build ID (for ELF binaries, the code
/// ID IS the build ID). Callers must provide a real code_id — either from the
/// `--code-id` CLI flag or from the `INFO CODE_ID` record in the `.sym` file.
/// Deriving a build ID from the debug ID is not attempted because the Breakpad
/// debug ID only preserves 16 of the 20 bytes in a standard SHA-1 build ID,
/// and debuginfod requires an exact match.
pub async fn fetch_binary_debuginfod(
    client: &Client,
    cache: &Cache,
    config: &Config,
    code_file: &str,
    code_id: &str,
) -> Result<PathBuf> {
    let build_id = code_id.to_lowercase();

    // Use build_id as the cache code_id to avoid collisions with code_id-based lookups
    let key = BinaryCacheKey {
        code_file: code_file.to_string(),
        code_id: format!("buildid-{build_id}"),
        filename: code_file.to_string(),
    };

    // Check cache
    match cache.get_binary(&key) {
        CacheResult::Hit(path) => {
            info!("cache hit: {code_file} (buildid-{build_id})");
            return Ok(path);
        }
        CacheResult::NegativeHit => {
            debug!("negative cache hit: {code_file} (buildid-{build_id})");
            bail!("binary not available via debuginfod (cached negative result)");
        }
        CacheResult::Miss => {
            debug!("cache miss: {code_file} (buildid-{build_id})");
        }
    }

    if config.offline {
        bail!("binary not in cache and --offline is set: {code_file} (build ID: {build_id})");
    }

    info!(
        "trying debuginfod for {} (build ID: {}, {} server(s))",
        code_file,
        build_id,
        config.debuginfod_urls.len()
    );

    match debuginfod::fetch_executable(client, &build_id, &config.debuginfod_urls).await {
        FetchResult::Ok(data) => {
            let path = cache.store_binary(&key, &data)?;
            return Ok(path);
        }
        FetchResult::NotFound => {
            info!("debuginfod: {} not found on any server", code_file);
        }
        FetchResult::Error(e) => {
            warn!("debuginfod fetch error: {e}");
        }
    }

    cache.store_binary_miss(&key)?;
    bail!(
        "binary not found: {code_file} (build ID: {build_id})\n\
         Tried: debuginfod ({})",
        config.debuginfod_urls.join(", ")
    )
}

/// Create an HTTP client with extended timeout for large archive downloads.
pub fn build_archive_http_client(config: &Config) -> Result<Client> {
    Client::builder()
        .user_agent(&config.user_agent)
        .timeout(std::time::Duration::from_secs(
            config.archive_timeout_seconds,
        ))
        .redirect(reqwest::redirect::Policy::limited(10))
        .gzip(true)
        .build()
        .context("building archive HTTP client")
}

/// Fetch a Linux binary from Mozilla's FTP archive, checking cache first.
///
/// Uses the same `buildid-{id}` cache key format as debuginfod so that binaries
/// cached by either source are found by both. Does not store negative cache
/// markers because failure depends on user-provided version/channel metadata.
///
/// The .tar.xz archive itself is also cached so that extracting a second binary
/// from the same release does not require re-downloading.
pub async fn fetch_binary_ftp(
    client: &Client,
    cache: &Cache,
    config: &Config,
    code_file: &str,
    code_id: &str,
    locator: &archive::ArchiveLocator,
) -> Result<PathBuf> {
    let build_id = code_id.to_lowercase();

    // Use same cache key as debuginfod
    let key = BinaryCacheKey {
        code_file: code_file.to_string(),
        code_id: format!("buildid-{build_id}"),
        filename: code_file.to_string(),
    };

    // Check cache for extracted binary
    match cache.get_binary(&key) {
        CacheResult::Hit(path) => {
            info!("cache hit: {code_file} (buildid-{build_id})");
            return Ok(path);
        }
        CacheResult::NegativeHit | CacheResult::Miss => {
            debug!("cache miss (FTP): {code_file} (buildid-{build_id})");
        }
    }

    if config.offline {
        bail!("binary not in cache and --offline is set: {code_file} (build ID: {build_id})");
    }

    // Get archive bytes — from cache or download
    let (archive_filename, archive_id) = archive::archive_cache_key(locator)?;
    let archive_key = BinaryCacheKey {
        code_file: archive_filename.clone(),
        code_id: archive_id,
        filename: archive_filename,
    };

    let archive_data = match cache.get_binary(&archive_key) {
        CacheResult::Hit(path) => {
            info!("using cached archive: {}", path.display());
            std::fs::read(&path)
                .with_context(|| format!("reading cached archive: {}", path.display()))?
        }
        _ => {
            match archive::download_archive(client, locator).await {
                FetchResult::Ok(data) => {
                    // Cache the archive for future extractions
                    cache.store_binary(&archive_key, &data)?;
                    data
                }
                FetchResult::NotFound => {
                    bail!(
                        "FTP archive not found on server (HTTP 404) for {code_file}\n\
                         Check that --version and --channel are correct"
                    )
                }
                FetchResult::Error(e) => {
                    bail!("FTP archive download error: {e}")
                }
            }
        }
    };

    let binary_data =
        archive::extract_and_verify(&archive_data, code_file, &build_id, &locator.platform)
            .context("FTP archive extraction")?;

    let path = cache.store_binary(&key, &binary_data)?;
    Ok(path)
}

/// Fetch a Linux binary from a Snap Store package, checking cache first.
///
/// Uses the same `buildid-{id}` cache key format as debuginfod/FTP so that
/// binaries cached by any source are found by all. The snap archive itself is
/// also cached so that extracting a second binary from the same snap does not
/// require re-downloading.
pub async fn fetch_binary_snap(
    client: &Client,
    cache: &Cache,
    code_file: &str,
    code_id: &str,
    locator: &snap::SnapLocator,
) -> Result<PathBuf> {
    let build_id = code_id.to_lowercase();

    // Use same cache key as debuginfod/FTP
    let key = BinaryCacheKey {
        code_file: code_file.to_string(),
        code_id: format!("buildid-{build_id}"),
        filename: code_file.to_string(),
    };

    // Check cache for extracted binary
    match cache.get_binary(&key) {
        CacheResult::Hit(path) => {
            info!("cache hit: {code_file} (buildid-{build_id})");
            return Ok(path);
        }
        CacheResult::NegativeHit | CacheResult::Miss => {
            debug!("cache miss (snap): {code_file} (buildid-{build_id})");
        }
    }

    // Check if snap archive is already cached
    let (snap_filename, snap_cache_id) = snap::snap_cache_key(locator);
    let snap_key = BinaryCacheKey {
        code_file: snap_filename.clone(),
        code_id: snap_cache_id,
        filename: snap_filename,
    };

    let snap_path = match cache.get_binary(&snap_key) {
        CacheResult::Hit(path) => {
            info!("using cached snap: {}", path.display());
            path
        }
        _ => {
            // Query Snap Store and download
            let (download_url, revision) = snap::query_snap_store(client, locator).await?;
            info!(
                "downloading snap: {} rev {} ({:.0} ...)",
                locator.snap_name,
                revision,
                download_url.len()
            );

            let response = client
                .get(&download_url)
                .send()
                .await
                .context("downloading snap package")?;

            let status = response.status();
            if !status.is_success() {
                bail!("snap download failed: HTTP {status}");
            }

            let data = response
                .bytes()
                .await
                .context("reading snap package body")?
                .to_vec();

            info!(
                "downloaded snap: {} ({:.1} MB)",
                locator.snap_name,
                data.len() as f64 / 1_048_576.0
            );

            // Cache the snap archive
            cache.store_binary(&snap_key, &data)?
        }
    };

    // Extract binary from squashfs
    let binary_data =
        snap::extract_from_squashfs(&snap_path, code_file).context("snap extraction")?;

    // Verify build ID
    archive::verify_binary_id(&binary_data, &build_id).map_err(|e| {
        e.context(
            "the Snap Store only serves the current revision — \
             if the crash is from an older version, the binary \
             cannot be retrieved from this source",
        )
    })?;
    info!("build ID verified ({build_id})");

    let path = cache.store_binary(&key, &binary_data)?;
    Ok(path)
}

/// Fetch a Linux binary from an Ubuntu APT .deb package, checking cache first.
///
/// Uses the same `buildid-{id}` cache key format as debuginfod/FTP/snap so that
/// binaries cached by any source are found by all. The .deb archive itself is
/// also cached so that extracting a second binary from the same package does not
/// require re-downloading.
pub async fn fetch_binary_apt(
    client: &Client,
    cache: &Cache,
    code_file: &str,
    code_id: &str,
    locator: &apt::AptLocator,
    source_package: Option<&str>,
) -> Result<PathBuf> {
    let build_id = code_id.to_lowercase();

    // Use same cache key as debuginfod/FTP/snap
    let key = BinaryCacheKey {
        code_file: code_file.to_string(),
        code_id: format!("buildid-{build_id}"),
        filename: code_file.to_string(),
    };

    // Check cache for extracted binary
    match cache.get_binary(&key) {
        CacheResult::Hit(path) => {
            info!("cache hit: {code_file} (buildid-{build_id})");
            return Ok(path);
        }
        CacheResult::NegativeHit | CacheResult::Miss => {
            debug!("cache miss (apt): {code_file} (buildid-{build_id})");
        }
    }

    // Resolve package name and download URL from Packages.xz index
    let candidates = apt::resolve_package(client, cache, locator, source_package).await?;

    // Try each candidate .deb until we find one containing the target binary
    // with the correct build ID
    for (package_name, deb_url) in &candidates {
        // Check if .deb is already cached
        let (deb_filename, deb_cache_id) = apt::deb_cache_key(deb_url, locator);
        let deb_key = BinaryCacheKey {
            code_file: deb_filename.clone(),
            code_id: deb_cache_id,
            filename: deb_filename,
        };

        let deb_data = match cache.get_binary(&deb_key) {
            CacheResult::Hit(path) => {
                info!("using cached .deb: {} ({})", package_name, path.display());
                std::fs::read(&path)
                    .with_context(|| format!("reading cached .deb: {}", path.display()))?
            }
            _ => {
                match apt::download_deb(client, deb_url).await {
                    FetchResult::Ok(data) => {
                        // Cache the .deb
                        cache.store_binary(&deb_key, &data)?;
                        data
                    }
                    FetchResult::NotFound => {
                        debug!("deb not found: {deb_url}");
                        continue;
                    }
                    FetchResult::Error(e) => {
                        warn!("deb download error for {package_name}: {e}");
                        continue;
                    }
                }
            }
        };

        // Try extracting the target binary
        match apt::extract_from_deb(&deb_data, code_file) {
            Ok(binary_data) => {
                // Verify build ID
                match archive::verify_binary_id(&binary_data, &build_id) {
                    Ok(()) => {
                        info!("build ID verified ({build_id}) from package {package_name}");
                        let path = cache.store_binary(&key, &binary_data)?;
                        return Ok(path);
                    }
                    Err(e) => {
                        info!("build ID mismatch in {package_name}: {e}");
                        continue;
                    }
                }
            }
            Err(e) => {
                debug!("{code_file} not found in {package_name}: {e}");
                continue;
            }
        }
    }

    bail!(
        "binary not found in APT packages for {} ({}): tried {} candidate(s)",
        code_file,
        locator.release,
        candidates.len()
    )
}

/// Heuristic: file name looks like a Windows binary (PE).
/// Used to skip the Microsoft Symbol Server for non-Windows modules.
fn looks_like_windows_binary(code_file: &str) -> bool {
    let lower = code_file.to_ascii_lowercase();
    lower.ends_with(".dll")
        || lower.ends_with(".exe")
        || lower.ends_with(".sys")
        || lower.ends_with(".pdb")
}

/// Check if response data looks like an HTML error page rather than real data.
///
/// Some symbol servers return HTML error pages with 200 status codes. We check
/// the first 256 bytes for `<!DOCTYPE` or `<html` (case-insensitive) to detect
/// these corrupted responses.
fn is_html_response(data: &[u8]) -> bool {
    let prefix = &data[..data.len().min(256)];
    let lowercase: Vec<u8> = prefix.iter().map(|b| b.to_ascii_lowercase()).collect();
    let s = String::from_utf8_lossy(&lowercase);
    s.contains("<!doctype") || s.contains("<html")
}

/// Replace the last character of a file extension with '_'.
/// ntdll.dll -> ntdll.dl_, xul.dll -> xul.dl_
pub fn compress_filename(name: &str) -> String {
    let mut chars: Vec<char> = name.chars().collect();
    if chars.len() >= 2 {
        let last = chars.len() - 1;
        chars[last] = '_';
    }
    chars.into_iter().collect()
}

/// Decompress a CAB archive and return the contents of the first file.
pub fn decompress_cab(data: &[u8]) -> Result<Vec<u8>> {
    let cursor = std::io::Cursor::new(data);
    let mut cabinet = cab::Cabinet::new(cursor)?;

    let file_name = cabinet
        .folder_entries()
        .flat_map(|folder| folder.file_entries())
        .map(|entry| entry.name().to_string())
        .next()
        .ok_or_else(|| anyhow::anyhow!("CAB archive is empty"))?;

    let mut reader = cabinet.read_file(&file_name)?;
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sym_filename() {
        assert_eq!(sym_filename("xul.pdb"), "xul.sym");
        assert_eq!(sym_filename("libxul.so"), "libxul.so.sym");
        assert_eq!(sym_filename("XUL"), "XUL.sym");
        assert_eq!(sym_filename("ntdll.pdb"), "ntdll.sym");
    }

    #[test]
    fn test_looks_like_windows_binary() {
        assert!(looks_like_windows_binary("ntdll.dll"));
        assert!(looks_like_windows_binary("firefox.exe"));
        assert!(looks_like_windows_binary("win32kfull.sys"));
        assert!(looks_like_windows_binary("ntdll.pdb"));
        assert!(looks_like_windows_binary("WIN32K.SYS"));
        assert!(!looks_like_windows_binary("libxul.so"));
        assert!(!looks_like_windows_binary("XUL"));
    }

    #[test]
    fn test_is_html_response_doctype() {
        let data = b"<!DOCTYPE html><html><body>Not Found</body></html>";
        assert!(is_html_response(data));
    }

    #[test]
    fn test_is_html_response_html_tag() {
        let data = b"<HTML><HEAD><TITLE>Error</TITLE></HEAD></HTML>";
        assert!(is_html_response(data));
    }

    #[test]
    fn test_is_html_response_binary_data() {
        let data = b"MODULE windows x86_64 ABC123 xul.pdb\n";
        assert!(!is_html_response(data));
    }

    #[test]
    fn test_is_html_response_empty() {
        let data = b"";
        assert!(!is_html_response(data));
    }

    #[test]
    fn test_is_html_response_mz_header() {
        let data = b"MZ\x90\x00\x03\x00\x00\x00";
        assert!(!is_html_response(data));
    }
}
