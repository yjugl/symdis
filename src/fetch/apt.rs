// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::io::Read;

use anyhow::{bail, Context, Result};
use reqwest::Client;
use tracing::{debug, info};

use crate::cache::{BinaryCacheKey, Cache, CacheResult};
use crate::symbols::breakpad::SymFile;

use super::FetchResult;

const ARCHIVE_BASE: &str = "https://archive.ubuntu.com/ubuntu";
const PORTS_ARCHIVE_BASE: &str = "https://ports.ubuntu.com/ubuntu-ports";

/// Components to search in order.
const COMPONENTS: &[&str] = &["main", "universe"];

/// Parameters needed to locate a package in the Ubuntu APT archive.
pub struct AptLocator {
    /// Explicit binary package name, or None to auto-detect from source package.
    pub package: Option<String>,
    /// Ubuntu release codename (e.g., "noble", "jammy").
    pub release: String,
    /// Debian architecture (e.g., "amd64", "arm64").
    pub architecture: String,
}

/// Map a Breakpad .sym architecture string to a Debian architecture name.
pub fn apt_architecture(sym_arch: &str) -> Option<&'static str> {
    match sym_arch {
        "x86_64" => Some("amd64"),
        "x86" => Some("i386"),
        "arm64" | "aarch64" => Some("arm64"),
        "arm" => Some("armhf"),
        _ => None,
    }
}

/// Scan a SymFile's source file paths for Ubuntu APT build patterns.
///
/// Recognizes two path patterns:
/// 1. Build paths: `/build/<name>-<random>/<name>-<version>/...`
///    (from dpkg-buildpackage build directories)
/// 2. Debug source paths: `/usr/src/<name>-<version>/...`
///    (from dpkg debug symbol packages, e.g., `/usr/src/glib2.0-2.80.0-6ubuntu3.8/...`)
///
/// Build paths are distinct from snap paths which have `/build/<snap>/parts/...`.
pub fn detect_apt_source_package(sym_file: &SymFile) -> Option<String> {
    for path in &sym_file.files {
        if let Some(name) = extract_apt_source_name(path) {
            return Some(name.to_string());
        }
        if let Some(name) = extract_usr_src_source_name(path) {
            return Some(name.to_string());
        }
    }
    None
}

/// Extract the source package name from a single path with APT build pattern.
///
/// Pattern: `/build/<name>-<random>/<name>-<version>/...`
/// The source name is the longest common prefix between the first directory
/// component (without the random suffix) and the second directory component
/// (without the version suffix).
fn extract_apt_source_name(path: &str) -> Option<&str> {
    let rest = path.split("/build/").nth(1)?;
    let parts: Vec<&str> = rest.splitn(3, '/').collect();
    if parts.len() < 2 {
        return None;
    }
    let dir_with_random = parts[0]; // e.g., "libxml2-2gYHdD"
    let dir_with_version = parts[1]; // e.g., "libxml2-2.9.13+dfsg"

    // Skip snap paths (they have /parts/ after the name)
    if parts.len() >= 3 && parts[1] == "parts" {
        return None;
    }
    // Also skip if the second component is "parts"
    if dir_with_version == "parts" {
        return None;
    }

    if dir_with_random.is_empty() || dir_with_version.is_empty() {
        return None;
    }

    // The source name is the longest common prefix of the two directory names,
    // but we need to strip the trailing hyphen and suffix from each.
    // Find the longest common prefix ending at a '-' boundary.
    let prefix = longest_common_prefix_at_dash(dir_with_random, dir_with_version)?;

    if prefix.is_empty() {
        return None;
    }

    Some(prefix)
}

/// Extract the source package name from a `/usr/src/<name>-<version>/` path.
///
/// Ubuntu debug symbol packages install source files under `/usr/src/<srcpkg>-<version>/`.
/// Per Debian policy, upstream versions start with a digit, so we split at the first
/// `-` followed by a digit to separate source package name from version.
///
/// Examples:
///   `/usr/src/glib2.0-2.80.0-6ubuntu3.8/gobject/gtype.c` → `glib2.0`
///   `/usr/src/libxml2-2.9.14+dfsg-1.3build3/parser.c` → `libxml2`
///   `/usr/src/mesa-24.0.5-1ubuntu2/src/gallium/foo.c` → `mesa`
fn extract_usr_src_source_name(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/usr/src/")?;

    // Get the first path component (the directory name)
    let dir_name = rest.split('/').next()?;
    if dir_name.is_empty() {
        return None;
    }

    // Find the first '-' followed by a digit: that's where the version starts.
    // The source package name is everything before that '-'.
    let bytes = dir_name.as_bytes();
    for i in 0..bytes.len().saturating_sub(1) {
        if bytes[i] == b'-' && bytes[i + 1].is_ascii_digit() {
            if i == 0 {
                return None;
            }
            return Some(&dir_name[..i]);
        }
    }

    None
}

/// Find the longest common prefix of two strings that ends right before a '-'.
/// Returns the prefix without the trailing '-'.
///
/// For "libxml2-2gYHdD" and "libxml2-2.9.13+dfsg":
///   common prefix = "libxml2-2" but we want to return at a '-' boundary.
///   Actually we need the last '-' that's part of the common prefix structure.
///
/// The logic: both strings share the source package name, followed by '-' and
/// then different suffixes. We find the longest leading substring that ends at
/// a '-' boundary where the next parts diverge.
fn longest_common_prefix_at_dash<'a>(a: &'a str, b: &str) -> Option<&'a str> {
    // Find character-by-character common prefix length
    let common_len = a.bytes().zip(b.bytes()).take_while(|(x, y)| x == y).count();

    // Find the last '-' in the common prefix portion of `a`.
    let common = &a[..common_len];

    // We want the last '-' position: the source name is everything before it.
    // E.g., common="libxml2-2" → last '-' at 7 → source name = "libxml2"
    // E.g., common="mesa-" → last '-' at 4 → source name = "mesa"
    // E.g., common="glib2.0-" → last '-' at 7 → source name = "glib2.0"
    let last_dash = common.rfind('-')?;
    if last_dash == 0 {
        return None;
    }
    Some(&a[..last_dash])
}

/// Resolve a package to its download URL by searching Packages.xz indices.
///
/// Returns `(package_name, download_path)` where download_path is relative
/// to the archive root (e.g., "pool/main/l/libxml2/libxml2_2.9.14+dfsg-1.3build3_amd64.deb").
pub async fn resolve_package(
    client: &Client,
    cache: &Cache,
    locator: &AptLocator,
    source_package: Option<&str>,
) -> Result<Vec<(String, String)>> {
    let explicit_package = locator.package.as_deref();
    let search_name = explicit_package.or(source_package).ok_or_else(|| {
        anyhow::anyhow!(
            "cannot determine package name: use --apt <package_name> or ensure \
             the sym file contains Ubuntu build paths"
        )
    })?;

    // Determine archive base URL based on architecture
    // ports.ubuntu.com for arm64/armhf/etc, archive.ubuntu.com for amd64/i386
    let archive_base = if locator.architecture == "amd64" || locator.architecture == "i386" {
        ARCHIVE_BASE
    } else {
        PORTS_ARCHIVE_BASE
    };

    // Search the base release, -updates, and -security pockets.
    // Updated packages (security fixes, SRUs) live in -updates/-security,
    // not the base release. We collect candidates from ALL pockets so that
    // build ID verification can find the correct version.
    let pockets = [
        locator.release.clone(),
        format!("{}-updates", locator.release),
        format!("{}-security", locator.release),
    ];

    let mut all_candidates = Vec::new();

    for pocket in &pockets {
        for component in COMPONENTS {
            let packages_data = fetch_packages_index(
                client,
                cache,
                archive_base,
                pocket,
                component,
                &locator.architecture,
            )
            .await;

            let packages_data = match packages_data {
                Ok(data) => data,
                Err(e) => {
                    debug!("failed to fetch Packages.xz for {pocket}/{component}: {e}");
                    continue;
                }
            };

            let candidates = if explicit_package.is_some() {
                // Search by Package: field (binary package name)
                find_packages_by_name(&packages_data, search_name)
            } else {
                // Search by Source: field (source package name)
                find_packages_by_source(&packages_data, search_name)
            };

            for (name, path) in candidates {
                all_candidates.push((name.to_string(), format!("{archive_base}/{path}")));
            }
        }
    }

    if all_candidates.is_empty() {
        bail!(
            "package '{search_name}' not found in APT index for {} {}",
            locator.release,
            locator.architecture
        );
    }

    Ok(all_candidates)
}

/// Fetch and decompress a Packages.xz index file, with caching.
async fn fetch_packages_index(
    client: &Client,
    cache: &Cache,
    archive_base: &str,
    release: &str,
    component: &str,
    architecture: &str,
) -> Result<Vec<u8>> {
    // Cache key: Packages.xz/<release>-<component>-<arch>/Packages.xz
    let cache_filename = "Packages.xz".to_string();
    let cache_id = format!("{release}-{component}-{architecture}");
    let key = BinaryCacheKey {
        code_file: cache_filename.clone(),
        code_id: cache_id,
        filename: cache_filename,
    };

    // Check cache
    match cache.get_binary(&key) {
        CacheResult::Hit(path) => {
            debug!("using cached Packages index: {}", path.display());
            let compressed = std::fs::read(&path)
                .with_context(|| format!("reading cached Packages.xz: {}", path.display()))?;
            return decompress_xz(&compressed);
        }
        CacheResult::NegativeHit | CacheResult::Miss => {
            debug!("Packages index cache miss: {release}/{component}/{architecture}");
        }
    }

    let url =
        format!("{archive_base}/dists/{release}/{component}/binary-{architecture}/Packages.xz");
    info!("downloading APT index: {url}");

    let response = client
        .get(&url)
        .send()
        .await
        .context("downloading Packages.xz")?;

    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        bail!("Packages.xz not found: {url}");
    }
    if !status.is_success() {
        bail!("Packages.xz download failed: HTTP {status}");
    }

    let compressed = response
        .bytes()
        .await
        .context("reading Packages.xz response")?
        .to_vec();

    info!(
        "downloaded Packages.xz ({:.1} KB compressed)",
        compressed.len() as f64 / 1024.0
    );

    // Cache the compressed index
    cache.store_binary(&key, &compressed)?;

    decompress_xz(&compressed)
}

/// Decompress xz-compressed data.
fn decompress_xz(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = liblzma::read::XzDecoder::new(data);
    let mut buf = Vec::new();
    decoder
        .read_to_end(&mut buf)
        .context("decompressing Packages.xz")?;
    Ok(buf)
}

/// Find packages by binary package name (Package: field).
/// Returns `(package_name, filename)` pairs.
fn find_packages_by_name<'a>(data: &'a [u8], name: &str) -> Vec<(&'a str, &'a str)> {
    let text = match std::str::from_utf8(data) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };

    let mut results = Vec::new();
    for stanza in PackagesIter::new(text) {
        if stanza.package == Some(name) {
            if let Some(filename) = stanza.filename {
                results.push((stanza.package.unwrap(), filename));
            }
        }
    }
    results
}

/// Find packages by source package name (Source: field).
/// Returns `(package_name, filename)` pairs for all binary packages from that source.
fn find_packages_by_source<'a>(data: &'a [u8], source_name: &str) -> Vec<(&'a str, &'a str)> {
    let text = match std::str::from_utf8(data) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };

    let mut results = Vec::new();
    for stanza in PackagesIter::new(text) {
        let matches = if let Some(source) = stanza.source {
            // Source: field may contain version in parens: "libxml2 (1:2.9.14+dfsg-1.3build3)"
            let source_name_part = source.split_whitespace().next().unwrap_or(source);
            source_name_part == source_name
        } else if let Some(pkg) = stanza.package {
            // When Source: is absent, the source package name equals the binary package name
            pkg == source_name
        } else {
            false
        };

        if matches {
            if let (Some(pkg), Some(filename)) = (stanza.package, stanza.filename) {
                results.push((pkg, filename));
            }
        }
    }
    results
}

/// Parsed fields from a single stanza in a Packages file.
struct PackageStanza<'a> {
    package: Option<&'a str>,
    source: Option<&'a str>,
    filename: Option<&'a str>,
}

/// Iterator over stanzas in a Packages file.
struct PackagesIter<'a> {
    remaining: &'a str,
}

impl<'a> PackagesIter<'a> {
    fn new(text: &'a str) -> Self {
        Self { remaining: text }
    }
}

impl<'a> Iterator for PackagesIter<'a> {
    type Item = PackageStanza<'a>;

    fn next(&mut self) -> Option<PackageStanza<'a>> {
        loop {
            if self.remaining.is_empty() {
                return None;
            }

            // Find the next blank line (stanza separator)
            let (stanza_text, rest) = match self.remaining.find("\n\n") {
                Some(pos) => (&self.remaining[..pos], &self.remaining[pos + 2..]),
                None => (self.remaining, ""),
            };

            self.remaining = rest;

            if stanza_text.trim().is_empty() {
                continue;
            }

            let mut package = None;
            let mut source = None;
            let mut filename = None;

            for line in stanza_text.lines() {
                if let Some(val) = line.strip_prefix("Package: ") {
                    package = Some(val.trim());
                } else if let Some(val) = line.strip_prefix("Source: ") {
                    source = Some(val.trim());
                } else if let Some(val) = line.strip_prefix("Filename: ") {
                    filename = Some(val.trim());
                }
            }

            if package.is_some() || filename.is_some() {
                return Some(PackageStanza {
                    package,
                    source,
                    filename,
                });
            }
        }
    }
}

/// Download a .deb package.
pub async fn download_deb(client: &Client, url: &str) -> FetchResult {
    info!("downloading .deb from {url}");

    let response = match client.get(url).send().await {
        Ok(r) => r,
        Err(e) => return FetchResult::Error(format!("deb download request failed: {e}")),
    };

    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return FetchResult::NotFound;
    }
    if !status.is_success() {
        return FetchResult::Error(format!("deb download failed: HTTP {status}"));
    }

    match response.bytes().await {
        Ok(bytes) => {
            info!(
                "downloaded .deb ({:.1} MB)",
                bytes.len() as f64 / 1_048_576.0
            );
            FetchResult::Ok(bytes.to_vec())
        }
        Err(e) => FetchResult::Error(format!("reading deb response body: {e}")),
    }
}

/// Extract a file from a .deb package.
///
/// A .deb is an `ar` archive containing `data.tar.{zst,xz,gz}` which holds
/// the actual installed files. This function:
/// 1. Parses the ar archive to find the data.tar.* member
/// 2. Decompresses it (zstd, xz, or gzip)
/// 3. Extracts the target file from the tar archive
pub fn extract_from_deb(data: &[u8], target_name: &str) -> Result<Vec<u8>> {
    // Parse ar archive
    let data_member = find_ar_member(data, "data.tar")?;

    // Detect compression and decompress
    let tar_data = decompress_deb_data(data_member)?;

    // Extract target from tar
    extract_from_tar(&tar_data, target_name)
}

/// Parse an `ar` archive and find a member whose name starts with `prefix`.
///
/// AR format:
///   - Global header: "!<arch>\n" (8 bytes)
///   - Per-entry header (60 bytes):
///     - name: 16 bytes (padded with spaces, may end with '/')
///     - modification time: 12 bytes
///     - owner ID: 6 bytes
///     - group ID: 6 bytes
///     - mode: 8 bytes
///     - size: 10 bytes (decimal, space-padded)
///     - magic: "`\n" (2 bytes)
///   - Data: `size` bytes, padded to 2-byte alignment
fn find_ar_member<'a>(data: &'a [u8], name_prefix: &str) -> Result<&'a [u8]> {
    const AR_MAGIC: &[u8] = b"!<arch>\n";
    const HEADER_SIZE: usize = 60;

    if data.len() < AR_MAGIC.len() || &data[..AR_MAGIC.len()] != AR_MAGIC {
        bail!("not an ar archive (bad magic)");
    }

    let mut pos = AR_MAGIC.len();

    while pos + HEADER_SIZE <= data.len() {
        let header = &data[pos..pos + HEADER_SIZE];

        // Check entry magic
        if header[58] != b'`' || header[59] != b'\n' {
            bail!("invalid ar entry header at offset {pos}");
        }

        // Parse name (first 16 bytes)
        let name_raw = std::str::from_utf8(&header[..16]).context("ar entry name is not UTF-8")?;
        let name = name_raw.trim_end_matches([' ', '/']);

        // Parse size (bytes 48-57)
        let size_str = std::str::from_utf8(&header[48..58])
            .context("ar entry size is not UTF-8")?
            .trim();
        let size: usize = size_str
            .parse()
            .with_context(|| format!("invalid ar entry size: '{size_str}'"))?;

        let data_start = pos + HEADER_SIZE;
        let data_end = data_start + size;

        if data_end > data.len() {
            bail!("ar entry extends beyond file: {name}");
        }

        if name.starts_with(name_prefix) {
            debug!("found ar member: {name} ({size} bytes)");
            return Ok(&data[data_start..data_end]);
        }

        // Advance to next entry (2-byte aligned)
        pos = data_end + (data_end % 2);
    }

    bail!("'{name_prefix}*' member not found in ar archive")
}

/// Decompress data.tar.* based on magic bytes.
fn decompress_deb_data(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 4 {
        bail!("data.tar member too short to detect compression");
    }

    // zstd magic: 0x28 0xB5 0x2F 0xFD
    if data[0] == 0x28 && data[1] == 0xB5 && data[2] == 0x2F && data[3] == 0xFD {
        debug!("data.tar compression: zstd");
        let mut buf = Vec::new();
        let mut decoder =
            zstd::stream::read::Decoder::new(data).context("creating zstd decoder")?;
        decoder
            .read_to_end(&mut buf)
            .context("decompressing data.tar.zst")?;
        return Ok(buf);
    }

    // xz magic: 0xFD 0x37 0x7A 0x58 0x5A 0x00
    if data.len() >= 6 && &data[..6] == b"\xfd7zXZ\x00" {
        debug!("data.tar compression: xz");
        let mut buf = Vec::new();
        let mut decoder = liblzma::read::XzDecoder::new(data);
        decoder
            .read_to_end(&mut buf)
            .context("decompressing data.tar.xz")?;
        return Ok(buf);
    }

    // gzip magic: 0x1F 0x8B
    if data[0] == 0x1F && data[1] == 0x8B {
        debug!("data.tar compression: gzip");
        let mut buf = Vec::new();
        let mut decoder = flate2::read::GzDecoder::new(data);
        decoder
            .read_to_end(&mut buf)
            .context("decompressing data.tar.gz")?;
        return Ok(buf);
    }

    bail!("unrecognized data.tar compression format (expected zstd, xz, or gzip)")
}

/// Extract a file from a tar archive by matching the last path component.
///
/// Handles symlinks: in .deb packages, shared libraries like `libfoo.so.0` are
/// often symlinks to the versioned file `libfoo.so.0.8000.0`. When the target
/// name matches a symlink, we follow the link to extract the real file.
fn extract_from_tar(tar_data: &[u8], target_name: &str) -> Result<Vec<u8>> {
    // First pass: look for exact filename match (regular file or symlink)
    let mut archive = tar::Archive::new(tar_data);
    let mut symlink_target: Option<String> = None;

    for entry in archive.entries().context("reading tar entries")? {
        let mut entry = entry.context("reading tar entry")?;
        let path = entry.path().context("reading entry path")?;

        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        if filename == target_name {
            let entry_type = entry.header().entry_type();
            if entry_type == tar::EntryType::Regular || entry_type == tar::EntryType::GNUSparse {
                debug!(
                    "found '{}' in deb data.tar at '{}'",
                    target_name,
                    path.display()
                );
                let mut buf = Vec::new();
                entry.read_to_end(&mut buf).context("reading tar entry")?;
                return Ok(buf);
            }
            if entry_type == tar::EntryType::Symlink || entry_type == tar::EntryType::Link {
                if let Ok(Some(link)) = entry.link_name() {
                    let link_name = link
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("")
                        .to_string();
                    if !link_name.is_empty() {
                        debug!("'{}' is a symlink to '{}'", target_name, link_name);
                        symlink_target = Some(link_name);
                    }
                }
            }
        }
    }

    // Second pass: follow symlink target
    if let Some(ref link_name) = symlink_target {
        let mut archive = tar::Archive::new(tar_data);
        for entry in archive
            .entries()
            .context("reading tar entries (symlink follow)")?
        {
            let mut entry = entry.context("reading tar entry")?;
            let path = entry.path().context("reading entry path")?;
            let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            if filename == link_name {
                let entry_type = entry.header().entry_type();
                if entry_type == tar::EntryType::Regular || entry_type == tar::EntryType::GNUSparse
                {
                    debug!(
                        "found symlink target '{}' at '{}'",
                        link_name,
                        path.display()
                    );
                    let mut buf = Vec::new();
                    entry.read_to_end(&mut buf).context("reading tar entry")?;
                    return Ok(buf);
                }
            }
        }
    }

    bail!("file '{target_name}' not found in .deb data.tar")
}

/// Compute the cache key for a .deb archive.
///
/// Uses the actual .deb filename from the URL (which includes version) to avoid
/// cache collisions between different versions of the same package across
/// pockets (e.g., noble vs noble-updates).
///
/// Layout: `<deb_filename> / <release>-<arch> / <deb_filename>`
pub fn deb_cache_key(deb_url: &str, locator: &AptLocator) -> (String, String) {
    // Extract filename from URL: ".../libglib2.0-0t64_2.80.0-6ubuntu3.8_amd64.deb"
    let filename = deb_url
        .rsplit('/')
        .next()
        .unwrap_or("package.deb")
        .to_string();
    let cache_id = format!("{}-{}", locator.release, locator.architecture);
    (filename, cache_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apt_architecture() {
        assert_eq!(apt_architecture("x86_64"), Some("amd64"));
        assert_eq!(apt_architecture("x86"), Some("i386"));
        assert_eq!(apt_architecture("arm64"), Some("arm64"));
        assert_eq!(apt_architecture("aarch64"), Some("arm64"));
        assert_eq!(apt_architecture("arm"), Some("armhf"));
        assert_eq!(apt_architecture("ppc"), None);
        assert_eq!(apt_architecture(""), None);
    }

    #[test]
    fn test_detect_apt_source_package_libxml2() {
        let sym_file = SymFile::parse(std::io::Cursor::new(
            "MODULE Linux x86_64 ABC123 libxml2.so.2\n\
             FILE 0 /build/libxml2-2gYHdD/libxml2-2.9.13+dfsg/parser.c\n\
             FILE 1 /build/libxml2-2gYHdD/libxml2-2.9.13+dfsg/tree.c\n",
        ))
        .unwrap();
        assert_eq!(
            detect_apt_source_package(&sym_file),
            Some("libxml2".to_string())
        );
    }

    #[test]
    fn test_detect_apt_source_package_mesa() {
        let sym_file = SymFile::parse(std::io::Cursor::new(
            "MODULE Linux x86_64 ABC123 libgallium-24.0.5.so\n\
             FILE 0 /build/mesa-JhNbTR/mesa-24.0.5/src/gallium/drivers/radeonsi/si_shader.c\n",
        ))
        .unwrap();
        assert_eq!(
            detect_apt_source_package(&sym_file),
            Some("mesa".to_string())
        );
    }

    #[test]
    fn test_detect_apt_source_package_libdrm() {
        let sym_file = SymFile::parse(std::io::Cursor::new(
            "MODULE Linux x86_64 ABC123 libdrm.so.2\n\
             FILE 0 /build/libdrm-FbhG3x/libdrm-2.4.120/xf86drm.c\n",
        ))
        .unwrap();
        assert_eq!(
            detect_apt_source_package(&sym_file),
            Some("libdrm".to_string())
        );
    }

    #[test]
    fn test_detect_apt_source_package_glib2() {
        // Source package name with dots and digits
        let sym_file = SymFile::parse(std::io::Cursor::new(
            "MODULE Linux x86_64 ABC123 libglib-2.0.so.0\n\
             FILE 0 /build/glib2.0-A3kYj2/glib2.0-2.80.0/glib/gmain.c\n",
        ))
        .unwrap();
        assert_eq!(
            detect_apt_source_package(&sym_file),
            Some("glib2.0".to_string())
        );
    }

    #[test]
    fn test_detect_apt_source_package_not_snap() {
        // Snap paths should NOT be detected as APT
        let sym_file = SymFile::parse(std::io::Cursor::new(
            "MODULE Linux x86_64 ABC123 libglib-2.0.so.0\n\
             FILE 0 /build/gnome-42-2204-sdk/parts/glib/src/glib/gmain.c\n",
        ))
        .unwrap();
        assert_eq!(detect_apt_source_package(&sym_file), None);
    }

    #[test]
    fn test_detect_apt_source_package_none() {
        // Mozilla build paths should not match
        let sym_file = SymFile::parse(std::io::Cursor::new(
            "MODULE Linux x86_64 ABC123 libxul.so\n\
             FILE 0 /builds/worker/workspace/build/src/xpcom/base/nsCOMPtr.cpp\n",
        ))
        .unwrap();
        assert_eq!(detect_apt_source_package(&sym_file), None);
    }

    #[test]
    fn test_extract_apt_source_name() {
        assert_eq!(
            extract_apt_source_name("/build/libxml2-2gYHdD/libxml2-2.9.13+dfsg/parser.c"),
            Some("libxml2")
        );
        assert_eq!(
            extract_apt_source_name("/build/mesa-JhNbTR/mesa-24.0.5/src/gallium/foo.c"),
            Some("mesa")
        );
        assert_eq!(
            extract_apt_source_name("/build/libdrm-FbhG3x/libdrm-2.4.120/xf86drm.c"),
            Some("libdrm")
        );
    }

    #[test]
    fn test_extract_apt_source_name_snap_path() {
        // Snap paths should be rejected
        assert_eq!(
            extract_apt_source_name("/build/gnome-42-2204-sdk/parts/glib/src/glib/gmain.c"),
            None
        );
    }

    #[test]
    fn test_extract_usr_src_source_name() {
        assert_eq!(
            extract_usr_src_source_name("/usr/src/glib2.0-2.80.0-6ubuntu3.8/gobject/gtype.c"),
            Some("glib2.0")
        );
        assert_eq!(
            extract_usr_src_source_name("/usr/src/libxml2-2.9.14+dfsg-1.3build3/parser.c"),
            Some("libxml2")
        );
        assert_eq!(
            extract_usr_src_source_name("/usr/src/mesa-24.0.5-1ubuntu2/src/gallium/foo.c"),
            Some("mesa")
        );
        assert_eq!(
            extract_usr_src_source_name("/usr/src/libdrm-2.4.120-2build1/xf86drm.c"),
            Some("libdrm")
        );
    }

    #[test]
    fn test_extract_usr_src_source_name_no_match() {
        // Not a /usr/src/ path
        assert_eq!(
            extract_usr_src_source_name("/build/libxml2-2gYHdD/libxml2-2.9.13+dfsg/parser.c"),
            None
        );
        // No version
        assert_eq!(extract_usr_src_source_name("/usr/src/nodashes/foo.c"), None);
    }

    #[test]
    fn test_detect_apt_source_package_usr_src() {
        let sym_file = SymFile::parse(std::io::Cursor::new(
            "MODULE Linux x86_64 ABC123 libgobject-2.0.so.0\n\
             FILE 0 /usr/src/glib2.0-2.80.0-6ubuntu3.8/gobject/gtype.c\n",
        ))
        .unwrap();
        assert_eq!(
            detect_apt_source_package(&sym_file),
            Some("glib2.0".to_string())
        );
    }

    #[test]
    fn test_extract_apt_source_name_no_match() {
        assert_eq!(
            extract_apt_source_name("/usr/src/linux-headers-5.15.0/fs/ext4/super.c"),
            None
        );
        assert_eq!(
            extract_apt_source_name("/builds/worker/workspace/build/src/foo.c"),
            None
        );
    }

    #[test]
    fn test_longest_common_prefix_at_dash() {
        assert_eq!(
            longest_common_prefix_at_dash("libxml2-2gYHdD", "libxml2-2.9.13+dfsg"),
            Some("libxml2")
        );
        assert_eq!(
            longest_common_prefix_at_dash("mesa-JhNbTR", "mesa-24.0.5"),
            Some("mesa")
        );
        assert_eq!(
            longest_common_prefix_at_dash("libdrm-FbhG3x", "libdrm-2.4.120"),
            Some("libdrm")
        );
        assert_eq!(
            longest_common_prefix_at_dash("glib2.0-A3kYj2", "glib2.0-2.80.0"),
            Some("glib2.0")
        );
    }

    #[test]
    fn test_longest_common_prefix_at_dash_no_match() {
        assert_eq!(longest_common_prefix_at_dash("abc", "def"), None);
        assert_eq!(longest_common_prefix_at_dash("", ""), None);
    }

    #[test]
    fn test_find_packages_by_name() {
        let data = b"\
Package: libxml2
Source: libxml2 (2.9.14+dfsg-1.3build3)
Architecture: amd64
Filename: pool/main/libx/libxml2/libxml2_2.9.14+dfsg-1.3build3_amd64.deb

Package: libxml2-dev
Source: libxml2 (2.9.14+dfsg-1.3build3)
Architecture: amd64
Filename: pool/main/libx/libxml2/libxml2-dev_2.9.14+dfsg-1.3build3_amd64.deb

";
        let results = find_packages_by_name(data, "libxml2");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "libxml2");
        assert!(results[0].1.contains("libxml2_2.9.14"));
    }

    #[test]
    fn test_find_packages_by_source() {
        let data = b"\
Package: libxml2
Source: libxml2 (2.9.14+dfsg-1.3build3)
Architecture: amd64
Filename: pool/main/libx/libxml2/libxml2_2.9.14+dfsg-1.3build3_amd64.deb

Package: libxml2-dev
Source: libxml2 (2.9.14+dfsg-1.3build3)
Architecture: amd64
Filename: pool/main/libx/libxml2/libxml2-dev_2.9.14+dfsg-1.3build3_amd64.deb

Package: unrelated
Source: other-package
Architecture: amd64
Filename: pool/main/o/other-package/unrelated_1.0_amd64.deb

";
        let results = find_packages_by_source(data, "libxml2");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "libxml2");
        assert_eq!(results[1].0, "libxml2-dev");
    }

    #[test]
    fn test_find_packages_by_source_implicit() {
        // When Source: is absent, binary package name == source name
        let data = b"\
Package: mesa-common-dev
Architecture: amd64
Filename: pool/main/m/mesa/mesa-common-dev_24.0.5-1_amd64.deb

";
        let results = find_packages_by_source(data, "mesa-common-dev");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "mesa-common-dev");
    }

    /// Build an ar entry header (exactly 60 bytes).
    fn make_ar_header(name: &str, size: usize) -> Vec<u8> {
        // name(16) + mtime(12) + uid(6) + gid(6) + mode(8) + size(10) + magic(2) = 60
        let header = format!(
            "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            name, "0", "0", "0", "100644", size
        );
        assert_eq!(header.len(), 60, "ar header must be exactly 60 bytes");
        header.into_bytes()
    }

    #[test]
    fn test_find_ar_member() {
        let mut ar_data = Vec::new();
        ar_data.extend_from_slice(b"!<arch>\n");

        // Member 1: "debian-binary" with content "2.0\n"
        let content1 = b"2.0\n";
        ar_data.extend_from_slice(&make_ar_header("debian-binary", content1.len()));
        ar_data.extend_from_slice(content1);

        // Member 2: "data.tar.zst" with content "fake"
        let content2 = b"fake";
        ar_data.extend_from_slice(&make_ar_header("data.tar.zst", content2.len()));
        ar_data.extend_from_slice(content2);

        let result = find_ar_member(&ar_data, "data.tar").unwrap();
        assert_eq!(result, b"fake");
    }

    #[test]
    fn test_find_ar_member_not_found() {
        let mut ar_data = Vec::new();
        ar_data.extend_from_slice(b"!<arch>\n");

        let content = b"2.0\n";
        ar_data.extend_from_slice(&make_ar_header("debian-binary", content.len()));
        ar_data.extend_from_slice(content);

        let result = find_ar_member(&ar_data, "data.tar");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_find_ar_member_bad_magic() {
        let result = find_ar_member(b"not an ar archive", "data.tar");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("not an ar archive"));
    }

    #[test]
    fn test_decompress_deb_data_gzip() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let original = b"test tar data content";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let result = decompress_deb_data(&compressed).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn test_decompress_deb_data_unknown() {
        let result = decompress_deb_data(&[0x00, 0x00, 0x00, 0x00]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unrecognized"));
    }

    #[test]
    fn test_deb_cache_key() {
        let locator = AptLocator {
            package: Some("libxml2".to_string()),
            release: "noble".to_string(),
            architecture: "amd64".to_string(),
        };
        let url = "https://archive.ubuntu.com/ubuntu/pool/main/libx/libxml2/libxml2_2.9.14+dfsg-1.3build3_amd64.deb";
        let (filename, cache_id) = deb_cache_key(url, &locator);
        assert_eq!(filename, "libxml2_2.9.14+dfsg-1.3build3_amd64.deb");
        assert_eq!(cache_id, "noble-amd64");
    }

    #[test]
    fn test_packages_iter() {
        let text = "\
Package: libfoo
Source: foo (1.0-1)
Filename: pool/main/f/foo/libfoo_1.0-1_amd64.deb

Package: libbar
Filename: pool/main/b/bar/libbar_2.0_amd64.deb

";
        let stanzas: Vec<_> = PackagesIter::new(text).collect();
        assert_eq!(stanzas.len(), 2);
        assert_eq!(stanzas[0].package, Some("libfoo"));
        assert_eq!(stanzas[0].source, Some("foo (1.0-1)"));
        assert_eq!(
            stanzas[0].filename,
            Some("pool/main/f/foo/libfoo_1.0-1_amd64.deb")
        );
        assert_eq!(stanzas[1].package, Some("libbar"));
        assert_eq!(stanzas[1].source, None);
        assert_eq!(
            stanzas[1].filename,
            Some("pool/main/b/bar/libbar_2.0_amd64.deb")
        );
    }

    #[test]
    fn test_packages_iter_empty() {
        let stanzas: Vec<_> = PackagesIter::new("").collect();
        assert_eq!(stanzas.len(), 0);
    }
}
