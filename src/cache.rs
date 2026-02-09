// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::path::{Path, PathBuf};

use anyhow::{Result, Context};

/// Represents the local cache for downloaded artifacts.
pub struct Cache {
    root: PathBuf,
    miss_ttl_hours: u64,
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
    pub fn new(root: &Path, miss_ttl_hours: u64) -> Self {
        Self {
            root: root.to_path_buf(),
            miss_ttl_hours,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Get the path where a symbol file would be cached.
    /// Layout matches WinDbg: <root>/<debug_file>/<debug_id>/<filename>
    pub fn sym_path(&self, key: &SymbolCacheKey) -> PathBuf {
        self.root
            .join(&key.debug_file)
            .join(&key.debug_id)
            .join(&key.filename)
    }

    /// Get the path where a binary file would be cached.
    /// Layout matches WinDbg: <root>/<code_file>/<code_id>/<code_file>
    pub fn binary_path(&self, key: &BinaryCacheKey) -> PathBuf {
        self.root
            .join(&key.code_file)
            .join(&key.code_id)
            .join(&key.filename)
    }

    /// Get the path for a negative cache marker.
    fn miss_path(&self, file: &str, id: &str) -> PathBuf {
        self.root
            .join("miss")
            .join(file)
            .join(format!("{}.miss", id))
    }

    /// Look up a symbol file in the cache.
    pub fn get_sym(&self, key: &SymbolCacheKey) -> CacheResult {
        let path = self.sym_path(key);
        if path.exists() {
            return CacheResult::Hit(path);
        }
        let miss = self.miss_path(&key.debug_file, &key.debug_id);
        if miss.exists() && !self.is_miss_expired(&miss) {
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
        let miss = self.miss_path(&key.code_file, &key.code_id);
        if miss.exists() && !self.is_miss_expired(&miss) {
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
        let miss = self.miss_path(&key.debug_file, &key.debug_id);
        self.atomic_write(&miss, b"")?;
        Ok(())
    }

    /// Store a negative cache marker for a binary.
    pub fn store_binary_miss(&self, key: &BinaryCacheKey) -> Result<()> {
        let miss = self.miss_path(&key.code_file, &key.code_id);
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

    /// Check if a miss marker has expired.
    fn is_miss_expired(&self, path: &Path) -> bool {
        let Ok(metadata) = std::fs::metadata(path) else {
            return true;
        };
        let Ok(modified) = metadata.modified() else {
            return true;
        };
        let Ok(elapsed) = modified.elapsed() else {
            return true;
        };
        elapsed > std::time::Duration::from_secs(self.miss_ttl_hours * 60 * 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path(), 24);

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
        let cache = Cache::new(dir.path(), 24);

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
