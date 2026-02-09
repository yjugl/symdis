// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

pub mod archive;
pub mod debuginfod;
pub mod microsoft;
pub mod tecken;

use std::path::PathBuf;

use anyhow::{Result, Context, bail};
use reqwest::Client;

use std::io::Read;

use crate::cache::{Cache, CacheResult, SymbolCacheKey, BinaryCacheKey};
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
        CacheResult::Hit(path) => return Ok(path),
        CacheResult::NegativeHit => bail!("symbol file not available (cached negative result)"),
        CacheResult::Miss => {}
    }

    // Try Tecken (first symbol server)
    let tecken_url = config.symbol_servers.first()
        .map(|s| s.as_str())
        .unwrap_or(tecken::DEFAULT_TECKEN_BASE);

    match tecken::fetch_sym(client, tecken_url, debug_file, debug_id).await {
        FetchResult::Ok(data) => {
            let path = cache.store_sym(&key, &data)?;
            return Ok(path);
        }
        FetchResult::NotFound => {}
        FetchResult::Error(e) => {
            eprintln!("warning: Tecken fetch error: {e}");
        }
    }

    // Store miss marker
    cache.store_sym_miss(&key)?;
    bail!(
        "symbol file not found: {debug_file}/{debug_id}/{sym_name}\n\
         Tried: Mozilla Tecken"
    )
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
        CacheResult::Hit(path) => return Ok(path),
        CacheResult::NegativeHit => bail!("binary not available (cached negative result)"),
        CacheResult::Miss => {}
    }

    // Try Tecken (code-file/code-id lookup)
    let tecken_url = config.symbol_servers.first()
        .map(|s| s.as_str())
        .unwrap_or(tecken::DEFAULT_TECKEN_BASE);

    match tecken::fetch_binary_by_code_id(client, tecken_url, code_file, code_id).await {
        FetchResult::Ok(data) => {
            let path = cache.store_binary(&key, &data)?;
            return Ok(path);
        }
        FetchResult::NotFound => {}
        FetchResult::Error(e) => {
            eprintln!("warning: Tecken binary fetch error: {e}");
        }
    }

    // Try Microsoft Symbol Server
    let ms_url = config.symbol_servers.get(1)
        .map(|s| s.as_str())
        .unwrap_or(microsoft::DEFAULT_MS_SYMBOL_SERVER);

    match microsoft::fetch_pe(client, ms_url, code_file, code_id).await {
        FetchResult::Ok(data) => {
            let path = cache.store_binary(&key, &data)?;
            return Ok(path);
        }
        FetchResult::NotFound => {}
        FetchResult::Error(e) => {
            eprintln!("warning: Microsoft symbol server fetch error: {e}");
        }
    }

    // Store miss marker
    cache.store_binary_miss(&key)?;
    bail!(
        "binary not found: {code_file}/{code_id}\n\
         Tried: Mozilla Tecken, Microsoft Symbol Server"
    )
}

/// Fetch a Linux binary via debuginfod, checking cache first.
///
/// If `code_id` is provided, it is used directly as the build ID (for ELF
/// binaries, the code ID IS the build ID). Otherwise, the build ID is derived
/// from the debug ID by reversing the GUID byte-swapping.
pub async fn fetch_binary_debuginfod(
    client: &Client,
    cache: &Cache,
    config: &Config,
    code_file: &str,
    code_id: Option<&str>,
    debug_id: &str,
) -> Result<PathBuf> {
    let build_id = match code_id {
        Some(id) => id.to_lowercase(),
        None => crate::symbols::id_convert::debug_id_to_build_id(debug_id)?,
    };

    // Use build_id as the cache code_id to avoid collisions with code_id-based lookups
    let key = BinaryCacheKey {
        code_file: code_file.to_string(),
        code_id: format!("buildid-{build_id}"),
        filename: code_file.to_string(),
    };

    // Check cache
    match cache.get_binary(&key) {
        CacheResult::Hit(path) => return Ok(path),
        CacheResult::NegativeHit => bail!("binary not available via debuginfod (cached negative result)"),
        CacheResult::Miss => {}
    }

    match debuginfod::fetch_executable(client, &build_id, &config.debuginfod_urls).await {
        FetchResult::Ok(data) => {
            let path = cache.store_binary(&key, &data)?;
            return Ok(path);
        }
        FetchResult::NotFound => {}
        FetchResult::Error(e) => {
            eprintln!("warning: debuginfod fetch error: {e}");
        }
    }

    cache.store_binary_miss(&key)?;
    bail!(
        "binary not found: {code_file} (build ID: {build_id})\n\
         Tried: debuginfod"
    )
}

/// Create an HTTP client with extended timeout for large archive downloads.
pub fn build_archive_http_client(config: &Config) -> Result<Client> {
    Client::builder()
        .user_agent(&config.user_agent)
        .timeout(std::time::Duration::from_secs(config.archive_timeout_seconds))
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
    code_file: &str,
    code_id: Option<&str>,
    debug_id: &str,
    locator: &archive::ArchiveLocator,
) -> Result<PathBuf> {
    let build_id = match code_id {
        Some(id) => id.to_lowercase(),
        None => crate::symbols::id_convert::debug_id_to_build_id(debug_id)?,
    };

    // Use same cache key as debuginfod
    let key = BinaryCacheKey {
        code_file: code_file.to_string(),
        code_id: format!("buildid-{build_id}"),
        filename: code_file.to_string(),
    };

    // Check cache for extracted binary
    match cache.get_binary(&key) {
        CacheResult::Hit(path) => return Ok(path),
        CacheResult::NegativeHit | CacheResult::Miss => {}
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
            eprintln!("info: using cached archive: {}", path.display());
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
                        "binary not found in FTP archive: {code_file}\n\
                         Check that --version and --channel are correct"
                    )
                }
                FetchResult::Error(e) => {
                    bail!("FTP archive download error: {e}")
                }
            }
        }
    };

    // Extract binary from archive and verify build ID
    let binary_data = archive::extract_and_verify(&archive_data, code_file, &build_id, &locator.platform)
        .context("FTP archive extraction")?;

    let path = cache.store_binary(&key, &binary_data)?;
    Ok(path)
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
}
