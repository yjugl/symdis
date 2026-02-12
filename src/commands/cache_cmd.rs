// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::fmt::Write;
use std::path::Path;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};

use super::{CacheAction, CacheArgs};
use crate::cache::Cache;
use crate::config::Config;

pub fn run(args: CacheArgs, config: &Config) -> Result<()> {
    let cache = Cache::new(&config.cache_dir, config.miss_ttl_hours);
    match args.action {
        CacheAction::Path => {
            println!("{}", cache.root().display());
            Ok(())
        }
        CacheAction::Size => {
            let root = cache.root();
            if !root.exists() {
                println!("0 B (cache directory does not exist)");
                return Ok(());
            }
            let (total_bytes, file_count) = walk_size(root)?;
            println!("{} ({} files)", format_size(total_bytes), file_count);
            Ok(())
        }
        CacheAction::Clear { older_than } => {
            let root = cache.root();
            if !root.exists() {
                println!("Cache directory does not exist, nothing to clear.");
                return Ok(());
            }
            let removed = clear_cache(root, older_than)?;
            if let Some(days) = older_than {
                println!("Removed {removed} files older than {days} days.");
            } else {
                println!("Removed {removed} files.");
            }
            Ok(())
        }
        CacheAction::List { debug_file } => {
            let root = cache.root();
            let module_dir = root.join(&debug_file);
            if !module_dir.exists() {
                println!("No cached artifacts for '{debug_file}'.");
                return Ok(());
            }
            let output = list_module(&module_dir, &debug_file)?;
            print!("{output}");
            Ok(())
        }
    }
}

/// Recursively walk a directory and sum all file sizes.
fn walk_size(dir: &Path) -> Result<(u64, usize)> {
    let mut total: u64 = 0;
    let mut count: usize = 0;
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("reading directory: {}", dir.display()))?;
    for entry in entries {
        let entry = entry?;
        let ft = entry.file_type()?;
        if ft.is_dir() {
            let (sub_total, sub_count) = walk_size(&entry.path())?;
            total += sub_total;
            count += sub_count;
        } else if ft.is_file() {
            total += entry.metadata()?.len();
            count += 1;
        }
    }
    Ok((total, count))
}

/// Delete cached files, optionally filtering by age.
fn clear_cache(root: &Path, older_than_days: Option<u64>) -> Result<usize> {
    let cutoff = older_than_days.map(|days| {
        SystemTime::now() - Duration::from_secs(days * 24 * 60 * 60)
    });
    let mut removed = 0;
    remove_files_recursive(root, cutoff, &mut removed)?;
    // Clean up empty directories after removing files
    remove_empty_dirs(root)?;
    Ok(removed)
}

/// Recursively remove files, optionally filtered by modification time.
fn remove_files_recursive(
    dir: &Path,
    cutoff: Option<SystemTime>,
    removed: &mut usize,
) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("reading directory: {}", dir.display()))?;
    for entry in entries {
        let entry = entry?;
        let ft = entry.file_type()?;
        if ft.is_dir() {
            remove_files_recursive(&entry.path(), cutoff, removed)?;
        } else if ft.is_file() {
            let should_remove = match cutoff {
                Some(cutoff_time) => {
                    let modified = entry.metadata()?.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                    modified < cutoff_time
                }
                None => true,
            };
            if should_remove {
                std::fs::remove_file(entry.path())
                    .with_context(|| format!("removing file: {}", entry.path().display()))?;
                *removed += 1;
            }
        }
    }
    Ok(())
}

/// Remove empty directories bottom-up. Returns true if the directory itself was removed.
fn remove_empty_dirs(dir: &Path) -> Result<bool> {
    let entries: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("reading directory: {}", dir.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut all_removed = true;
    for entry in &entries {
        if entry.file_type()?.is_dir() {
            if !remove_empty_dirs(&entry.path())? {
                all_removed = false;
            }
        } else {
            all_removed = false;
        }
    }
    if all_removed && entries.is_empty() {
        // Don't remove the root cache dir itself
        return Ok(false);
    }
    if all_removed {
        std::fs::remove_dir(dir).ok();
        return Ok(true);
    }
    Ok(false)
}

/// List cached artifacts for a module directory.
/// Layout: <root>/<debug_file>/<debug_id>/<files...>
fn list_module(module_dir: &Path, debug_file: &str) -> Result<String> {
    let mut out = String::new();
    let entries = std::fs::read_dir(module_dir)
        .with_context(|| format!("reading directory: {}", module_dir.display()))?;
    let mut id_dirs: Vec<_> = entries.filter_map(|e| e.ok()).collect();
    id_dirs.sort_by_key(|e| e.file_name());

    let mut found_any = false;
    for id_entry in &id_dirs {
        if !id_entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
            continue;
        }
        let id = id_entry.file_name();
        let id_str = id.to_string_lossy();
        let id_path = id_entry.path();
        let files = std::fs::read_dir(&id_path)
            .with_context(|| format!("reading directory: {}", id_path.display()))?;
        let mut file_entries: Vec<_> = files.filter_map(|e| e.ok()).collect();
        file_entries.sort_by_key(|e| e.file_name());

        for file_entry in &file_entries {
            if !file_entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
                continue;
            }
            let fname = file_entry.file_name();
            let size = file_entry.metadata().map(|m| m.len()).unwrap_or(0);
            writeln!(
                out,
                "{}/{}/{} ({})",
                debug_file,
                id_str,
                fname.to_string_lossy(),
                format_size(size)
            )
            .unwrap();
            found_any = true;
        }
    }

    if !found_any {
        writeln!(out, "No cached artifacts for '{debug_file}'.").unwrap();
    }

    Ok(out)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_walk_size_empty() {
        let dir = tempfile::tempdir().unwrap();
        let (total, count) = walk_size(dir.path()).unwrap();
        assert_eq!(total, 0);
        assert_eq!(count, 0);
    }

    #[test]
    fn test_walk_size_with_files() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("test.pdb").join("AABB");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("test.sym"), "hello").unwrap();
        std::fs::write(sub.join("test.dll"), "world!").unwrap();

        let (total, count) = walk_size(dir.path()).unwrap();
        assert_eq!(total, 11); // 5 + 6
        assert_eq!(count, 2);
    }

    #[test]
    fn test_clear_cache_all() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("mod.pdb").join("CCDD");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("mod.sym"), "data").unwrap();
        std::fs::write(sub.join("mod.dll"), "data").unwrap();

        let removed = clear_cache(dir.path(), None).unwrap();
        assert_eq!(removed, 2);
        // Files should be gone
        assert!(!sub.join("mod.sym").exists());
        assert!(!sub.join("mod.dll").exists());
    }

    #[test]
    fn test_clear_cache_older_than() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("mod.pdb").join("EEFF");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("recent.sym"), "data").unwrap();

        // Files just created should NOT be older than 1 day
        let removed = clear_cache(dir.path(), Some(1)).unwrap();
        assert_eq!(removed, 0);
        assert!(sub.join("recent.sym").exists());
    }

    #[test]
    fn test_list_module() {
        let dir = tempfile::tempdir().unwrap();
        let module_dir = dir.path().join("test.pdb");
        let id_dir = module_dir.join("AABB1122");
        std::fs::create_dir_all(&id_dir).unwrap();
        std::fs::write(id_dir.join("test.sym"), "symbol data here").unwrap();

        let output = list_module(&module_dir, "test.pdb").unwrap();
        assert!(output.contains("test.pdb/AABB1122/test.sym"));
        assert!(output.contains("16 B"));
    }

    #[test]
    fn test_list_module_empty() {
        let dir = tempfile::tempdir().unwrap();
        let module_dir = dir.path().join("empty.pdb");
        std::fs::create_dir_all(&module_dir).unwrap();

        let output = list_module(&module_dir, "empty.pdb").unwrap();
        assert!(output.contains("No cached artifacts"));
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1_048_576), "1.0 MB");
        assert_eq!(format_size(1_073_741_824), "1.0 GB");
    }
}
