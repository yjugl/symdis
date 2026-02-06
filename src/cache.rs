use std::path::{Path, PathBuf};

use anyhow::{Result, Context};

/// Represents the local cache for downloaded artifacts.
pub struct Cache {
    root: PathBuf,
}

/// Result of a cache lookup.
pub enum CacheResult {
    /// File found in cache.
    Hit(PathBuf),
    /// File not in cache and no negative marker.
    Miss,
    /// A negative cache marker exists (confirmed 404, within TTL).
    NegativeHit,
}

/// Cache key for symbol files.
pub struct SymbolCacheKey {
    pub debug_file: String,
    pub debug_id: String,
    pub filename: String,
}

/// Cache key for binary files.
pub struct BinaryCacheKey {
    pub code_file: String,
    pub code_id: String,
    pub filename: String,
}

impl Cache {
    pub fn new(override_dir: Option<&Path>) -> Result<Self> {
        let root = if let Some(dir) = override_dir {
            dir.to_path_buf()
        } else {
            Self::resolve_cache_dir()?
        };
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolve the cache directory per spec precedence:
    /// 1. Explicit override (--cache-dir)
    /// 2. SYMDIS_CACHE_DIR env var
    /// 3. _NT_SYMBOL_PATH (Windows) - extract first local cache path
    /// 4. Platform defaults
    fn resolve_cache_dir() -> Result<PathBuf> {
        // Check SYMDIS_CACHE_DIR env var
        if let Ok(dir) = std::env::var("SYMDIS_CACHE_DIR") {
            if !dir.is_empty() {
                return Ok(PathBuf::from(dir));
            }
        }

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

    /// Get the path where a symbol file would be cached.
    pub fn sym_path(&self, key: &SymbolCacheKey) -> PathBuf {
        self.root
            .join("symbols")
            .join(&key.debug_file)
            .join(&key.debug_id)
            .join(&key.filename)
    }

    /// Get the path where a binary file would be cached.
    pub fn binary_path(&self, key: &BinaryCacheKey) -> PathBuf {
        self.root
            .join("binaries")
            .join(&key.code_file)
            .join(&key.code_id)
            .join(&key.filename)
    }

    /// Get the path for a negative cache marker.
    fn miss_path(&self, category: &str, file: &str, id: &str) -> PathBuf {
        self.root
            .join("miss")
            .join(category)
            .join(file)
            .join(format!("{}.miss", id))
    }

    /// Look up a symbol file in the cache.
    pub fn get_sym(&self, key: &SymbolCacheKey) -> CacheResult {
        let path = self.sym_path(key);
        if path.exists() {
            return CacheResult::Hit(path);
        }
        let miss = self.miss_path("symbols", &key.debug_file, &key.debug_id);
        if miss.exists() && !Self::is_miss_expired(&miss) {
            return CacheResult::NegativeHit;
        }
        CacheResult::Miss
    }

    /// Look up a binary file in the cache.
    pub fn get_binary(&self, key: &BinaryCacheKey) -> CacheResult {
        let path = self.binary_path(key);
        if path.exists() {
            return CacheResult::Hit(path);
        }
        let miss = self.miss_path("binaries", &key.code_file, &key.code_id);
        if miss.exists() && !Self::is_miss_expired(&miss) {
            return CacheResult::NegativeHit;
        }
        CacheResult::Miss
    }

    /// Store data in the cache atomically.
    pub fn store_sym(&self, key: &SymbolCacheKey, data: &[u8]) -> Result<PathBuf> {
        let path = self.sym_path(key);
        self.atomic_write(&path, data)?;
        Ok(path)
    }

    /// Store binary data in the cache atomically.
    pub fn store_binary(&self, key: &BinaryCacheKey, data: &[u8]) -> Result<PathBuf> {
        let path = self.binary_path(key);
        self.atomic_write(&path, data)?;
        Ok(path)
    }

    /// Store a negative cache marker.
    pub fn store_sym_miss(&self, key: &SymbolCacheKey) -> Result<()> {
        let miss = self.miss_path("symbols", &key.debug_file, &key.debug_id);
        self.atomic_write(&miss, b"")?;
        Ok(())
    }

    /// Store a negative cache marker for a binary.
    pub fn store_binary_miss(&self, key: &BinaryCacheKey) -> Result<()> {
        let miss = self.miss_path("binaries", &key.code_file, &key.code_id);
        self.atomic_write(&miss, b"")?;
        Ok(())
    }

    /// Write data atomically: write to temp file, then rename.
    fn atomic_write(&self, target: &Path, data: &[u8]) -> Result<()> {
        use std::io::Write;

        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating directory {}", parent.display()))?;
        }

        let parent = target.parent().unwrap_or(Path::new("."));
        let mut tmp = tempfile::NamedTempFile::new_in(parent)
            .context("creating temp file")?;
        tmp.write_all(data).context("writing temp file")?;
        tmp.flush()?;

        // On Windows, persist handles rename-over-existing
        tmp.persist(target)
            .with_context(|| format!("persisting to {}", target.display()))?;

        Ok(())
    }

    /// Check if a miss marker has expired (default TTL: 24 hours).
    fn is_miss_expired(path: &Path) -> bool {
        let Ok(metadata) = std::fs::metadata(path) else {
            return true;
        };
        let Ok(modified) = metadata.modified() else {
            return true;
        };
        let Ok(elapsed) = modified.elapsed() else {
            return true;
        };
        elapsed > std::time::Duration::from_secs(24 * 60 * 60)
    }
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
fn parse_nt_symbol_path(sym_path: &str) -> Option<PathBuf> {
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
            original_rest.split_once('*').map(|(_, after_dll)| after_dll)
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

    // --- srv* tests ---

    #[test]
    fn test_srv_with_cache_and_server() {
        // srv*<cache>*<server> — standard form
        let path = parse_nt_symbol_path(
            "SRV*C:\\Symbols*https://msdl.microsoft.com/download/symbols",
        );
        assert_eq!(path, Some(PathBuf::from("C:\\Symbols")));
    }

    #[test]
    fn test_srv_chained() {
        // First entry wins
        let path = parse_nt_symbol_path(
            "SRV*C:\\Sym1*https://server1;SRV*C:\\Sym2*https://server2",
        );
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
        // srv*<url> with no local cache — nothing to extract
        assert_eq!(
            parse_nt_symbol_path("srv*https://msdl.microsoft.com/download/symbols"),
            None,
        );
    }

    #[test]
    fn test_srv_server_only_skipped_then_cache_found() {
        // First entry has no cache, second does
        let path = parse_nt_symbol_path(
            "SRV*https://server1;SRV*C:\\Symbols*https://server2",
        );
        assert_eq!(path, Some(PathBuf::from("C:\\Symbols")));
    }

    // --- cache* tests ---

    #[test]
    fn test_cache_with_dir() {
        // cache*<dir>;srv*<server> — recommended form from MS docs
        let path = parse_nt_symbol_path(
            "cache*C:\\MySymbols;srv*https://msdl.microsoft.com/download/symbols",
        );
        assert_eq!(path, Some(PathBuf::from("C:\\MySymbols")));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_cache_no_dir_default() {
        // cache*; with no dir — returns WinDbg default C:\ProgramData\Dbg\sym if it
        // exists on disk, otherwise falls through to later entries.
        let path = parse_nt_symbol_path(
            "cache*;srv*https://msdl.microsoft.com/download/symbols",
        );
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
        // cache* (no dir): returns WinDbg default if it exists, otherwise
        // falls through to the srv* entry which has a local cache.
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

    // --- symsrv* tests ---

    #[test]
    fn test_symsrv_with_dll_cache_server() {
        // Older verbose form: symsrv*symsrv.dll*<cache>*<server>
        let path = parse_nt_symbol_path(
            "symsrv*symsrv.dll*C:\\Symbols*https://msdl.microsoft.com/download/symbols",
        );
        assert_eq!(path, Some(PathBuf::from("C:\\Symbols")));
    }

    #[test]
    fn test_symsrv_no_cache() {
        // symsrv*symsrv.dll*<server> — no local cache
        assert_eq!(
            parse_nt_symbol_path("symsrv*symsrv.dll*https://msdl.microsoft.com"),
            None,
        );
    }

    // --- edge cases ---

    #[test]
    fn test_empty_string() {
        assert_eq!(parse_nt_symbol_path(""), None);
    }

    #[test]
    fn test_plain_local_path_ignored() {
        // Plain directory entries are not symbol server stores — skip
        assert_eq!(parse_nt_symbol_path("C:\\JustAPath"), None);
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_real_world_no_explicit_cache() {
        // Real-world value: cache* with no dir, srv* entries with no local cache.
        // Returns WinDbg default if it exists on disk, otherwise None.
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

    #[test]
    fn test_cache_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(Some(dir.path())).unwrap();

        let key = SymbolCacheKey {
            debug_file: "test.pdb".to_string(),
            debug_id: "AABBCCDD".to_string(),
            filename: "test.sym".to_string(),
        };

        // Initially a miss
        assert!(matches!(cache.get_sym(&key), CacheResult::Miss));

        // Store and retrieve
        let data = b"MODULE windows x86_64 AABBCCDD test.pdb\n";
        let path = cache.store_sym(&key, data).unwrap();
        assert!(path.exists());

        match cache.get_sym(&key) {
            CacheResult::Hit(p) => {
                assert_eq!(std::fs::read(&p).unwrap(), data);
            }
            _ => panic!("expected cache hit"),
        }
    }

    #[test]
    fn test_negative_cache() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(Some(dir.path())).unwrap();

        let key = SymbolCacheKey {
            debug_file: "missing.pdb".to_string(),
            debug_id: "00000000".to_string(),
            filename: "missing.sym".to_string(),
        };

        // Store miss marker
        cache.store_sym_miss(&key).unwrap();

        // Should be a negative hit
        assert!(matches!(cache.get_sym(&key), CacheResult::NegativeHit));
    }
}
