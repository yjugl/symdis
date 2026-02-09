// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::io::Read;

use anyhow::{Result, Context, bail};
use reqwest::Client;

use super::FetchResult;

const FTP_BASE: &str = "https://ftp.mozilla.org/pub/firefox";

/// Parameters needed to locate a Firefox build archive on the FTP server.
pub struct ArchiveLocator {
    pub version: String,
    pub channel: String,
    pub platform: String,
    pub build_id: Option<String>,
}

/// Map a Breakpad sym-file architecture string to the FTP platform directory name.
/// Returns `None` for non-Linux architectures.
pub fn ftp_platform(arch: &str) -> Option<&'static str> {
    match arch {
        "x86_64" => Some("linux-x86_64"),
        "x86" => Some("linux-i686"),
        "arm64" => Some("linux-aarch64"),
        _ => None,
    }
}

/// Construct the FTP archive URL for a given locator.
pub fn build_archive_url(locator: &ArchiveLocator) -> Result<String> {
    let platform = &locator.platform;
    let version = &locator.version;

    match locator.channel.as_str() {
        "release" => Ok(format!(
            "{FTP_BASE}/releases/{version}/{platform}/en-US/firefox-{version}.tar.xz"
        )),
        "beta" => Ok(format!(
            "{FTP_BASE}/releases/{version}/{platform}/en-US/firefox-{version}.tar.xz"
        )),
        "esr" => Ok(format!(
            "{FTP_BASE}/releases/{version}esr/{platform}/en-US/firefox-{version}esr.tar.xz"
        )),
        "nightly" => {
            let build_id = locator.build_id.as_deref()
                .ok_or_else(|| anyhow::anyhow!("--build-id is required for nightly channel"))?;
            // Build ID format: YYYYMMDDHHmmSS (14 digits)
            if build_id.len() != 14 || !build_id.chars().all(|c| c.is_ascii_digit()) {
                bail!("nightly build ID must be 14 digits (YYYYMMDDHHmmSS), got: {build_id}");
            }
            let year = &build_id[0..4];
            let month = &build_id[4..6];
            let day = &build_id[6..8];
            let hour = &build_id[8..10];
            let min = &build_id[10..12];
            let sec = &build_id[12..14];
            let timestamp = format!("{year}-{month}-{day}-{hour}-{min}-{sec}");
            Ok(format!(
                "{FTP_BASE}/nightly/{year}/{month}/{timestamp}-mozilla-central/firefox-{version}.en-US.{platform}.tar.xz"
            ))
        }
        other => bail!("unknown channel: {other} (expected: release, beta, esr, nightly)"),
    }
}

/// Extract a file from a tar.xz archive by matching the filename (ignoring directory prefix).
/// Returns the file contents as bytes.
pub fn extract_from_tar_xz(data: &[u8], target_name: &str) -> Result<Vec<u8>> {
    let decoder = xz2::read::XzDecoder::new(data);
    let mut archive = tar::Archive::new(decoder);

    for entry in archive.entries().context("reading tar entries")? {
        let mut entry = entry.context("reading tar entry")?;
        let path = entry.path().context("reading entry path")?;

        // Match by filename component only (ignore directory prefix like "firefox/")
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        if filename == target_name {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf).context("reading tar entry contents")?;
            return Ok(buf);
        }
    }

    bail!("file '{target_name}' not found in archive")
}

/// Extract the GNU build ID from an ELF binary's `.note.gnu.build-id` section.
///
/// Parses the raw ELF bytes with goblin, finds the section, then reads the
/// NT_GNU_BUILD_ID note structure.
pub fn extract_elf_build_id(data: &[u8]) -> Result<Option<String>> {
    let elf = goblin::elf::Elf::parse(data).context("parsing ELF for build ID")?;

    // Find .note.gnu.build-id section
    let note_section = elf.section_headers.iter().find(|sh| {
        elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("") == ".note.gnu.build-id"
    });

    let section = match note_section {
        Some(sh) => sh,
        None => return Ok(None),
    };

    let offset = section.sh_offset as usize;
    let size = section.sh_size as usize;

    if offset + size > data.len() {
        bail!(".note.gnu.build-id section extends beyond file");
    }

    let note_data = &data[offset..offset + size];
    parse_build_id_note(note_data)
}

/// Parse an ELF note structure to extract the build ID.
///
/// Note format:
///   u32 namesz (including null terminator)
///   u32 descsz
///   u32 type (NT_GNU_BUILD_ID = 3)
///   name (aligned to 4 bytes)
///   desc (the build ID bytes)
fn parse_build_id_note(data: &[u8]) -> Result<Option<String>> {
    const NT_GNU_BUILD_ID: u32 = 3;

    if data.len() < 12 {
        bail!("note too short: {} bytes", data.len());
    }

    let namesz = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let descsz = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    let note_type = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);

    if note_type != NT_GNU_BUILD_ID {
        return Ok(None);
    }

    // Name is padded to 4-byte alignment
    let name_aligned = (namesz + 3) & !3;
    let desc_start = 12 + name_aligned;
    let desc_end = desc_start + descsz;

    if desc_end > data.len() {
        bail!("build ID note desc extends beyond section");
    }

    let desc = &data[desc_start..desc_end];
    let hex: String = desc.iter().map(|b| format!("{b:02x}")).collect();
    Ok(Some(hex))
}

/// Verify that an ELF binary's build ID matches the expected value.
pub fn verify_build_id(data: &[u8], expected: &str) -> Result<()> {
    let actual = extract_elf_build_id(data)?
        .ok_or_else(|| anyhow::anyhow!("binary has no .note.gnu.build-id section"))?;

    if actual.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        bail!(
            "build ID mismatch: expected {expected}, got {actual}\n\
             The archive may contain a different build than expected"
        )
    }
}

/// Download a Firefox archive from the FTP server.
pub async fn download_archive(
    client: &Client,
    locator: &ArchiveLocator,
) -> FetchResult {
    let url = match build_archive_url(locator) {
        Ok(u) => u,
        Err(e) => return FetchResult::Error(format!("building archive URL: {e}")),
    };

    eprintln!("info: downloading archive from {url}");

    let response = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => return FetchResult::Error(format!("request failed: {e}")),
    };

    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return FetchResult::NotFound;
    }
    if !status.is_success() {
        return FetchResult::Error(format!("HTTP {status} from {url}"));
    }

    match response.bytes().await {
        Ok(b) => FetchResult::Ok(b.to_vec()),
        Err(e) => FetchResult::Error(format!("reading response body: {e}")),
    }
}

/// Extract a binary from archive bytes, then verify its build ID.
pub fn extract_and_verify(
    archive_data: &[u8],
    binary_name: &str,
    expected_build_id: &str,
) -> Result<Vec<u8>> {
    eprintln!(
        "info: extracting {binary_name} from archive ({:.1} MB)",
        archive_data.len() as f64 / 1_048_576.0
    );

    let binary_data = extract_from_tar_xz(archive_data, binary_name)
        .with_context(|| format!("extracting {binary_name}"))?;

    verify_build_id(&binary_data, expected_build_id)?;

    eprintln!("info: build ID verified ({expected_build_id})");

    Ok(binary_data)
}

/// Compute the cache key components for an archive file.
///
/// Returns `(archive_filename, cache_id)` suitable for a `BinaryCacheKey`.
/// Layout: `<archive_filename>/<channel>-<platform>/< archive_filename>`
pub fn archive_cache_key(locator: &ArchiveLocator) -> Result<(String, String)> {
    let url = build_archive_url(locator)?;
    // Extract filename from URL (last path component)
    let filename = url.rsplit('/').next().unwrap_or("archive.tar.xz").to_string();
    let cache_id = format!("{}-{}", locator.channel, locator.platform);
    Ok((filename, cache_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ftp_platform() {
        assert_eq!(ftp_platform("x86_64"), Some("linux-x86_64"));
        assert_eq!(ftp_platform("x86"), Some("linux-i686"));
        assert_eq!(ftp_platform("arm64"), Some("linux-aarch64"));
        assert_eq!(ftp_platform("arm"), None);
        assert_eq!(ftp_platform("ppc"), None);
    }

    #[test]
    fn test_build_archive_url_release() {
        let locator = ArchiveLocator {
            version: "147.0.3".to_string(),
            channel: "release".to_string(),
            platform: "linux-aarch64".to_string(),
            build_id: None,
        };
        let url = build_archive_url(&locator).unwrap();
        assert_eq!(
            url,
            "https://ftp.mozilla.org/pub/firefox/releases/147.0.3/linux-aarch64/en-US/firefox-147.0.3.tar.xz"
        );
    }

    #[test]
    fn test_build_archive_url_beta() {
        let locator = ArchiveLocator {
            version: "148.0b5".to_string(),
            channel: "beta".to_string(),
            platform: "linux-x86_64".to_string(),
            build_id: None,
        };
        let url = build_archive_url(&locator).unwrap();
        assert_eq!(
            url,
            "https://ftp.mozilla.org/pub/firefox/releases/148.0b5/linux-x86_64/en-US/firefox-148.0b5.tar.xz"
        );
    }

    #[test]
    fn test_build_archive_url_esr() {
        let locator = ArchiveLocator {
            version: "128.10.0".to_string(),
            channel: "esr".to_string(),
            platform: "linux-x86_64".to_string(),
            build_id: None,
        };
        let url = build_archive_url(&locator).unwrap();
        assert_eq!(
            url,
            "https://ftp.mozilla.org/pub/firefox/releases/128.10.0esr/linux-x86_64/en-US/firefox-128.10.0esr.tar.xz"
        );
    }

    #[test]
    fn test_build_archive_url_nightly() {
        let locator = ArchiveLocator {
            version: "149.0a1".to_string(),
            channel: "nightly".to_string(),
            platform: "linux-x86_64".to_string(),
            build_id: Some("20250601093042".to_string()),
        };
        let url = build_archive_url(&locator).unwrap();
        assert_eq!(
            url,
            "https://ftp.mozilla.org/pub/firefox/nightly/2025/06/2025-06-01-09-30-42-mozilla-central/firefox-149.0a1.en-US.linux-x86_64.tar.xz"
        );
    }

    #[test]
    fn test_build_archive_url_nightly_no_build_id() {
        let locator = ArchiveLocator {
            version: "149.0a1".to_string(),
            channel: "nightly".to_string(),
            platform: "linux-x86_64".to_string(),
            build_id: None,
        };
        assert!(build_archive_url(&locator).is_err());
    }

    #[test]
    fn test_build_archive_url_nightly_bad_build_id() {
        let locator = ArchiveLocator {
            version: "149.0a1".to_string(),
            channel: "nightly".to_string(),
            platform: "linux-x86_64".to_string(),
            build_id: Some("20250601".to_string()), // too short
        };
        assert!(build_archive_url(&locator).is_err());
    }

    #[test]
    fn test_build_archive_url_unknown_channel() {
        let locator = ArchiveLocator {
            version: "147.0".to_string(),
            channel: "aurora".to_string(),
            platform: "linux-x86_64".to_string(),
            build_id: None,
        };
        assert!(build_archive_url(&locator).is_err());
    }

    #[test]
    fn test_parse_build_id_note() {
        // Construct a valid NT_GNU_BUILD_ID note:
        // namesz=4 ("GNU\0"), descsz=20, type=3
        // name="GNU\0" (4 bytes, already 4-byte aligned)
        // desc=20 bytes of build ID
        let mut note = Vec::new();
        note.extend_from_slice(&4u32.to_le_bytes());   // namesz
        note.extend_from_slice(&20u32.to_le_bytes());  // descsz
        note.extend_from_slice(&3u32.to_le_bytes());   // type = NT_GNU_BUILD_ID
        note.extend_from_slice(b"GNU\0");              // name
        // 20 bytes of build ID
        let build_id_bytes: [u8; 20] = [
            0xe6, 0x15, 0x48, 0xbb, 0x7e, 0x61, 0xdf, 0xba, 0xe0, 0x4c,
            0x82, 0x88, 0xdc, 0x78, 0xc2, 0xbe, 0xcb, 0x85, 0xc9, 0x00,
        ];
        note.extend_from_slice(&build_id_bytes);

        let result = parse_build_id_note(&note).unwrap();
        assert_eq!(
            result,
            Some("e61548bb7e61dfbae04c8288dc78c2becb85c900".to_string())
        );
    }

    #[test]
    fn test_parse_build_id_note_wrong_type() {
        let mut note = Vec::new();
        note.extend_from_slice(&4u32.to_le_bytes());   // namesz
        note.extend_from_slice(&4u32.to_le_bytes());   // descsz
        note.extend_from_slice(&1u32.to_le_bytes());   // type = 1 (not build ID)
        note.extend_from_slice(b"GNU\0");
        note.extend_from_slice(&[0; 4]);

        let result = parse_build_id_note(&note).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_build_id_note_too_short() {
        let note = vec![0u8; 8]; // only 8 bytes, need at least 12
        assert!(parse_build_id_note(&note).is_err());
    }

    #[test]
    fn test_archive_cache_key_release() {
        let locator = ArchiveLocator {
            version: "147.0.3".to_string(),
            channel: "release".to_string(),
            platform: "linux-x86_64".to_string(),
            build_id: None,
        };
        let (filename, id) = archive_cache_key(&locator).unwrap();
        assert_eq!(filename, "firefox-147.0.3.tar.xz");
        assert_eq!(id, "release-linux-x86_64");
    }

    #[test]
    fn test_archive_cache_key_nightly() {
        let locator = ArchiveLocator {
            version: "149.0a1".to_string(),
            channel: "nightly".to_string(),
            platform: "linux-x86_64".to_string(),
            build_id: Some("20250601093042".to_string()),
        };
        let (filename, id) = archive_cache_key(&locator).unwrap();
        assert_eq!(filename, "firefox-149.0a1.en-US.linux-x86_64.tar.xz");
        assert_eq!(id, "nightly-linux-x86_64");
    }

    #[test]
    fn test_verify_build_id_mismatch() {
        // Minimal ELF with a build ID note — we'll test via extract + verify
        // For simplicity, just test verify_build_id returns error on non-ELF data
        let result = verify_build_id(&[0u8; 100], "abc123");
        assert!(result.is_err());
    }
}
