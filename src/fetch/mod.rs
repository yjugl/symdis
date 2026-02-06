pub mod microsoft;
pub mod tecken;

use std::path::PathBuf;

use anyhow::{Result, Context, bail};
use reqwest::Client;

use crate::cache::{Cache, CacheResult, SymbolCacheKey, BinaryCacheKey};

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
pub fn build_http_client() -> Result<Client> {
    Client::builder()
        .user_agent(format!("symdis/{}", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(30))
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

    // Try Tecken
    match tecken::fetch_sym(client, debug_file, debug_id).await {
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
    match tecken::fetch_binary_by_code_id(client, code_file, code_id).await {
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
    match microsoft::fetch_pe(client, code_file, code_id).await {
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
