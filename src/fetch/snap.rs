// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::path::Path;

use anyhow::{Result, Context, bail};
use reqwest::Client;
use tracing::{info, debug};

use crate::symbols::breakpad::SymFile;

const SNAP_STORE_API: &str = "https://api.snapcraft.io/v2/snaps/info";

/// Parameters needed to locate a snap package.
pub struct SnapLocator {
    pub snap_name: String,
    pub architecture: String,
}

/// Map a Breakpad .sym architecture string to a Snap Store architecture name.
/// Returns `None` for architectures not used with snaps.
pub fn snap_architecture(sym_arch: &str) -> Option<&'static str> {
    match sym_arch {
        "x86_64" => Some("amd64"),
        "x86" => Some("i386"),
        "arm64" | "aarch64" => Some("arm64"),
        "arm" => Some("armhf"),
        _ => None,
    }
}

/// Scan a SymFile's source file paths for `/build/<snap-name>/parts/` pattern.
///
/// Ubuntu snap builds compile inside `/build/<snap-name>/parts/...`, so the
/// source file paths in the .sym file reveal the snap package name.
pub fn detect_snap_name(sym_file: &SymFile) -> Option<String> {
    for path in &sym_file.files {
        if let Some(name) = extract_snap_name_from_path(path) {
            return Some(name.to_string());
        }
    }
    None
}

/// Extract the snap name from a single path containing `/build/<name>/parts/`.
fn extract_snap_name_from_path(path: &str) -> Option<&str> {
    let rest = path.split("/build/").nth(1)?;
    let name = rest.split('/').next()?;
    if name.is_empty() {
        return None;
    }
    // Verify the path continues with "/parts/" after the snap name
    let after_name = &rest[name.len()..];
    if after_name.starts_with("/parts/") {
        Some(name)
    } else {
        None
    }
}

/// Query the Snap Store API for a snap's download URL.
///
/// Returns `(download_url, revision)` for the latest stable-channel revision.
pub async fn query_snap_store(
    client: &Client,
    locator: &SnapLocator,
) -> Result<(String, String)> {
    let url = format!("{}/{}", SNAP_STORE_API, locator.snap_name);
    debug!("querying Snap Store: {} ({})", locator.snap_name, locator.architecture);

    let response = client
        .get(&url)
        .header("Snap-Device-Series", "16")
        .header("Snap-Device-Architecture", &locator.architecture)
        .send()
        .await
        .context("Snap Store API request failed")?;

    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        bail!("snap '{}' not found in Snap Store", locator.snap_name);
    }
    if !status.is_success() {
        bail!("Snap Store API returned HTTP {status}");
    }

    let body: serde_json::Value = response
        .json()
        .await
        .context("parsing Snap Store API response")?;

    // Find the latest/stable channel entry
    let channel_map = body["channel-map"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Snap Store response missing channel-map"))?;

    for entry in channel_map {
        let channel_name = entry["channel"]["name"].as_str().unwrap_or("");
        if channel_name == "stable" {
            let download_url = entry["download"]["url"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Snap Store entry missing download URL"))?
                .to_string();
            let revision = entry["revision"]
                .as_u64()
                .map(|r| r.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            info!(
                "Snap Store: {} rev {} ({})",
                locator.snap_name, revision, locator.architecture
            );
            return Ok((download_url, revision));
        }
    }

    bail!(
        "no stable channel found for snap '{}' ({})",
        locator.snap_name,
        locator.architecture
    )
}

/// Extract a file by name from a squashfs image on disk.
///
/// Walks all filesystem nodes and matches by filename (last path component),
/// since library locations vary between snap packages. If the match is a
/// symlink, the link target is resolved and extracted instead.
pub fn extract_from_squashfs(snap_path: &Path, target_filename: &str) -> Result<Vec<u8>> {
    use backhand::{FilesystemReader, InnerNode};

    info!("extracting {target_filename} from snap: {}", snap_path.display());

    let file = std::fs::File::open(snap_path)
        .with_context(|| format!("opening snap file: {}", snap_path.display()))?;
    let reader = std::io::BufReader::new(file);
    let fs = FilesystemReader::from_reader(reader)
        .context("reading squashfs from snap")?;

    // First pass: find the target by filename, resolving symlinks
    let mut real_filename = None;
    for node in fs.files() {
        let filename = node.fullpath.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        if filename == target_filename {
            match &node.inner {
                InnerNode::File(file_data) => {
                    return read_squashfs_file(&fs, file_data, target_filename);
                }
                InnerNode::Symlink(symlink) => {
                    // Symlink target is typically a relative name like "libglib-2.0.so.0.7800.1"
                    let link_target = symlink.link.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("");
                    debug!(
                        "{target_filename} is a symlink -> {}, resolving",
                        symlink.link.display()
                    );
                    real_filename = Some(link_target.to_string());
                    break;
                }
                _ => {}
            }
        }
    }

    // Second pass: if we found a symlink, extract its target
    if let Some(ref real_name) = real_filename {
        for node in fs.files() {
            let filename = node.fullpath.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            if filename == real_name {
                if let InnerNode::File(file_data) = &node.inner {
                    return read_squashfs_file(&fs, file_data, real_name);
                }
            }
        }
    }

    bail!("file '{target_filename}' not found in snap: {}", snap_path.display())
}

/// Read file data from a squashfs filesystem node.
fn read_squashfs_file(
    fs: &backhand::FilesystemReader<'_>,
    file_data: &backhand::SquashfsFileReader,
    name: &str,
) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut file_reader = fs.file(file_data).reader();
    std::io::Read::read_to_end(&mut file_reader, &mut buf)
        .context("reading file from squashfs")?;
    debug!("extracted {} ({} bytes) from snap", name, buf.len());
    Ok(buf)
}

/// Compute the cache key for a snap archive.
///
/// Layout: `<snap-name>.snap / <channel>-<arch> / <snap-name>.snap`
pub fn snap_cache_key(locator: &SnapLocator) -> (String, String) {
    let filename = format!("{}.snap", locator.snap_name);
    let cache_id = format!("stable-{}", locator.architecture);
    (filename, cache_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snap_architecture() {
        assert_eq!(snap_architecture("x86_64"), Some("amd64"));
        assert_eq!(snap_architecture("x86"), Some("i386"));
        assert_eq!(snap_architecture("arm64"), Some("arm64"));
        assert_eq!(snap_architecture("aarch64"), Some("arm64"));
        assert_eq!(snap_architecture("arm"), Some("armhf"));
        assert_eq!(snap_architecture("ppc"), None);
        assert_eq!(snap_architecture(""), None);
    }

    #[test]
    fn test_detect_snap_name() {
        let sym_file = SymFile::parse(std::io::Cursor::new(
            "MODULE Linux x86_64 8EF7C24A1B02B5A64F56BEA31DCF2B1E0 libglib-2.0.so.0\n\
             FILE 0 /build/gnome-42-2204-sdk/parts/glib/src/glib/gmain.c\n\
             FILE 1 /build/gnome-42-2204-sdk/parts/glib/src/glib/garray.c\n"
        )).unwrap();
        assert_eq!(detect_snap_name(&sym_file), Some("gnome-42-2204-sdk".to_string()));
    }

    #[test]
    fn test_detect_snap_name_none() {
        let sym_file = SymFile::parse(std::io::Cursor::new(
            "MODULE Linux x86_64 ABC123 libxul.so\n\
             FILE 0 /builds/worker/workspace/build/src/xpcom/base/nsCOMPtr.cpp\n\
             FILE 1 /usr/include/c++/11/bits/stl_vector.h\n"
        )).unwrap();
        assert_eq!(detect_snap_name(&sym_file), None);
    }

    #[test]
    fn test_extract_snap_name_from_path() {
        assert_eq!(
            extract_snap_name_from_path("/build/gnome-42-2204-sdk/parts/glib/src/glib/gmain.c"),
            Some("gnome-42-2204-sdk")
        );
        assert_eq!(
            extract_snap_name_from_path("/build/core22/parts/glibc/src/nptl/pthread_create.c"),
            Some("core22")
        );
        // No /parts/ after name
        assert_eq!(
            extract_snap_name_from_path("/build/something/other/path.c"),
            None
        );
        // Empty name
        assert_eq!(
            extract_snap_name_from_path("/build//parts/something"),
            None
        );
        // No /build/ prefix
        assert_eq!(
            extract_snap_name_from_path("/usr/src/gmain.c"),
            None
        );
    }

    #[test]
    fn test_snap_store_url_format() {
        // Verify the API URL construction
        let url = format!("{}/{}", SNAP_STORE_API, "gnome-42-2204-sdk");
        assert_eq!(url, "https://api.snapcraft.io/v2/snaps/info/gnome-42-2204-sdk");
    }

    #[test]
    fn test_snap_cache_key() {
        let locator = SnapLocator {
            snap_name: "gnome-42-2204-sdk".to_string(),
            architecture: "amd64".to_string(),
        };
        let (filename, cache_id) = snap_cache_key(&locator);
        assert_eq!(filename, "gnome-42-2204-sdk.snap");
        assert_eq!(cache_id, "stable-amd64");
    }
}
