// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::io::Read;

use anyhow::{Result, Context, bail};
use reqwest::Client;
use tracing::info;

use super::FetchResult;

const FTP_BASE: &str = "https://ftp.mozilla.org/pub/firefox";

/// Parameters needed to locate a Firefox build archive on the FTP server.
pub struct ArchiveLocator {
    pub version: String,
    pub channel: String,
    pub platform: String,
    pub build_id: Option<String>,
}

/// Map a Breakpad sym-file OS and architecture to the FTP platform directory name.
/// Returns `None` for unsupported OS/arch combinations.
pub fn ftp_platform(os: &str, arch: &str) -> Option<&'static str> {
    if os.eq_ignore_ascii_case("linux") {
        match arch {
            "x86_64" => Some("linux-x86_64"),
            "x86" => Some("linux-i686"),
            "arm64" => Some("linux-aarch64"),
            _ => None,
        }
    } else if os.eq_ignore_ascii_case("mac") {
        Some("mac") // Universal binary, single platform directory
    } else {
        None
    }
}

/// Construct the FTP archive URL for a given locator.
pub fn build_archive_url(locator: &ArchiveLocator) -> Result<String> {
    let platform = &locator.platform;
    let version = &locator.version;
    let is_mac = platform == "mac";

    match locator.channel.as_str() {
        "release" => {
            if is_mac {
                Ok(format!(
                    "{FTP_BASE}/releases/{version}/{platform}/en-US/Firefox%20{version}.pkg"
                ))
            } else {
                Ok(format!(
                    "{FTP_BASE}/releases/{version}/{platform}/en-US/firefox-{version}.tar.xz"
                ))
            }
        }
        "beta" => {
            if is_mac {
                Ok(format!(
                    "{FTP_BASE}/releases/{version}/{platform}/en-US/Firefox%20{version}.pkg"
                ))
            } else {
                Ok(format!(
                    "{FTP_BASE}/releases/{version}/{platform}/en-US/firefox-{version}.tar.xz"
                ))
            }
        }
        "esr" => {
            if is_mac {
                Ok(format!(
                    "{FTP_BASE}/releases/{version}esr/{platform}/en-US/Firefox%20{version}esr.pkg"
                ))
            } else {
                Ok(format!(
                    "{FTP_BASE}/releases/{version}esr/{platform}/en-US/firefox-{version}esr.tar.xz"
                ))
            }
        }
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
            if is_mac {
                Ok(format!(
                    "{FTP_BASE}/nightly/{year}/{month}/{timestamp}-mozilla-central/firefox-{version}.en-US.{platform}.pkg"
                ))
            } else {
                Ok(format!(
                    "{FTP_BASE}/nightly/{year}/{month}/{timestamp}-mozilla-central/firefox-{version}.en-US.{platform}.tar.xz"
                ))
            }
        }
        other => bail!("unknown channel: {other} (expected: release, beta, esr, nightly)"),
    }
}

/// Extract a file from a tar.xz archive by matching the filename (ignoring directory prefix).
/// Returns the file contents as bytes.
pub fn extract_from_tar_xz(data: &[u8], target_name: &str) -> Result<Vec<u8>> {
    let decoder = liblzma::read::XzDecoder::new(data);
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

/// Extract a file from a macOS `.pkg` (XAR) archive.
///
/// PKG files are XAR archives containing a gzip-compressed cpio Payload.
/// The XAR header and TOC are parsed to find the Payload, which is then
/// decompressed and searched for the target file.
pub fn extract_from_pkg(data: &[u8], target_name: &str) -> Result<Vec<u8>> {
    // XAR header: magic(4) + header_size(2) + version(2) + toc_compressed_len(8) + toc_uncompressed_len(8) + cksum_algo(4)
    const XAR_MAGIC: u32 = 0x78617221; // "xar!"

    if data.len() < 28 {
        bail!("XAR file too short: {} bytes", data.len());
    }

    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if magic != XAR_MAGIC {
        bail!("not a XAR archive (bad magic: 0x{:08x})", magic);
    }

    let header_size = u16::from_be_bytes([data[4], data[5]]) as usize;
    let toc_compressed_len = u64::from_be_bytes([
        data[8], data[9], data[10], data[11],
        data[12], data[13], data[14], data[15],
    ]) as usize;

    if header_size + toc_compressed_len > data.len() {
        bail!("XAR TOC extends beyond file");
    }

    // Decompress TOC (zlib-compressed XML)
    let toc_compressed = &data[header_size..header_size + toc_compressed_len];
    let mut toc_xml = Vec::new();
    let mut decoder = flate2::read::ZlibDecoder::new(toc_compressed);
    decoder.read_to_end(&mut toc_xml).context("decompressing XAR TOC")?;

    // Parse TOC XML to find the Payload file entry
    let heap_start = header_size + toc_compressed_len;
    let (payload_offset, payload_length) = parse_xar_toc_for_payload(&toc_xml)?;

    let abs_offset = heap_start + payload_offset;
    let abs_end = abs_offset + payload_length;
    if abs_end > data.len() {
        bail!("XAR Payload extends beyond file");
    }

    let payload_raw = &data[abs_offset..abs_end];

    // Decompress Payload — try gzip first (most common), then raw cpio
    let payload = if payload_raw.len() >= 2 && payload_raw[0] == 0x1f && payload_raw[1] == 0x8b {
        let mut buf = Vec::new();
        let mut gz_decoder = flate2::read::GzDecoder::new(payload_raw);
        gz_decoder.read_to_end(&mut buf).context("decompressing gzip PKG Payload")?;
        buf
    } else {
        payload_raw.to_vec()
    };

    // Search cpio archive for target file
    extract_from_cpio(&payload, target_name)
}

/// Parse XAR TOC XML to find the Payload file's heap offset and length.
///
/// In PKG files, the XML structure has `<data>` (with offset/length) BEFORE
/// `<name>`, so we collect all fields per `<file>` element and check the
/// name when we reach `</file>`.
fn parse_xar_toc_for_payload(toc_xml: &[u8]) -> Result<(usize, usize)> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    #[derive(Default)]
    struct FileContext {
        name: Option<String>,
        data_offset: Option<usize>,
        data_length: Option<usize>,
    }

    let mut reader = Reader::from_reader(toc_xml);
    let mut buf = Vec::new();

    // Stack of file contexts for nested <file> elements
    let mut file_stack: Vec<FileContext> = Vec::new();
    let mut path: Vec<String> = Vec::new();
    let mut current_text = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if tag == "file" {
                    file_stack.push(FileContext::default());
                }
                path.push(tag);
                current_text.clear();
            }
            Ok(Event::End(e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();

                // Capture fields from the current innermost <file> context
                if let Some(ctx) = file_stack.last_mut() {
                    if tag == "name" && ctx.name.is_none() {
                        ctx.name = Some(current_text.trim().to_string());
                    } else if tag == "offset" && path_contains(&path, "data") && ctx.data_offset.is_none() {
                        ctx.data_offset = current_text.trim().parse().ok();
                    } else if tag == "length" && path_contains(&path, "data") && ctx.data_length.is_none() {
                        ctx.data_length = current_text.trim().parse().ok();
                    }
                }

                // On </file>, check if this was the Payload file
                if tag == "file" {
                    if let Some(ctx) = file_stack.pop() {
                        if ctx.name.as_deref() == Some("Payload") {
                            if let (Some(off), Some(len)) = (ctx.data_offset, ctx.data_length) {
                                return Ok((off, len));
                            }
                        }
                    }
                }

                path.pop();
                current_text.clear();
            }
            Ok(Event::Text(e)) => {
                current_text.push_str(&String::from_utf8_lossy(e.as_ref()));
            }
            Ok(Event::Eof) => break,
            Err(e) => bail!("XAR TOC XML parse error: {e}"),
            _ => {}
        }
        buf.clear();
    }

    bail!("Payload not found in XAR TOC")
}

/// Check if any element in the path matches the given tag name.
fn path_contains(path: &[String], tag: &str) -> bool {
    path.iter().any(|t| t == tag)
}

/// Extract a file from a cpio archive by matching the last path component.
fn extract_from_cpio(data: &[u8], target_name: &str) -> Result<Vec<u8>> {
    for entry in cpio_reader::iter_files(data) {
        let name = entry.name();
        // Match by last path component
        let filename = name.rsplit('/').next().unwrap_or(name);
        if filename == target_name {
            return Ok(entry.file().to_vec());
        }
    }

    bail!("file '{target_name}' not found in cpio archive")
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
#[cfg(test)]
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

/// Verify a binary's identity by checking either ELF build ID or Mach-O UUID.
/// Tries ELF first, then Mach-O.
pub fn verify_binary_id(data: &[u8], expected: &str) -> Result<()> {
    // Try ELF build ID first
    if let Ok(Some(elf_id)) = extract_elf_build_id(data) {
        if elf_id.eq_ignore_ascii_case(expected) {
            return Ok(());
        } else {
            bail!(
                "build ID mismatch: expected {expected}, got {elf_id}\n\
                 The archive may contain a different build than expected"
            );
        }
    }

    // Try Mach-O UUID
    if let Ok(uuids) = crate::binary::macho::extract_macho_uuids(data) {
        if uuids.iter().any(|u| u.eq_ignore_ascii_case(expected)) {
            return Ok(());
        }
        if !uuids.is_empty() {
            bail!(
                "UUID mismatch: expected {expected}, got {}\n\
                 The archive may contain a different build than expected",
                uuids.join(", ")
            );
        }
    }

    bail!("cannot verify binary identity: neither ELF build ID nor Mach-O UUID found")
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

    info!("downloading archive from {url}");

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
///
/// The `platform` parameter determines the archive format:
/// - `"mac"` → PKG (XAR + cpio)
/// - anything else → tar.xz
pub fn extract_and_verify(
    archive_data: &[u8],
    binary_name: &str,
    expected_build_id: &str,
    platform: &str,
) -> Result<Vec<u8>> {
    info!(
        "extracting {binary_name} from archive ({:.1} MB)",
        archive_data.len() as f64 / 1_048_576.0
    );

    let binary_data = if platform == "mac" {
        extract_from_pkg(archive_data, binary_name)
            .with_context(|| format!("extracting {binary_name} from PKG"))?
    } else {
        extract_from_tar_xz(archive_data, binary_name)
            .with_context(|| format!("extracting {binary_name}"))?
    };

    verify_binary_id(&binary_data, expected_build_id)?;

    info!("build ID verified ({expected_build_id})");

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
    fn test_ftp_platform_linux() {
        assert_eq!(ftp_platform("linux", "x86_64"), Some("linux-x86_64"));
        assert_eq!(ftp_platform("linux", "x86"), Some("linux-i686"));
        assert_eq!(ftp_platform("linux", "arm64"), Some("linux-aarch64"));
        assert_eq!(ftp_platform("linux", "arm"), None);
        assert_eq!(ftp_platform("Linux", "x86_64"), Some("linux-x86_64"));
    }

    #[test]
    fn test_ftp_platform_mac() {
        assert_eq!(ftp_platform("mac", "x86_64"), Some("mac"));
        assert_eq!(ftp_platform("mac", "arm64"), Some("mac"));
        assert_eq!(ftp_platform("Mac", "arm64"), Some("mac"));
    }

    #[test]
    fn test_ftp_platform_unsupported() {
        assert_eq!(ftp_platform("windows", "x86_64"), None);
        assert_eq!(ftp_platform("", "x86_64"), None);
    }

    #[test]
    fn test_build_archive_url_release_linux() {
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
    fn test_build_archive_url_release_mac() {
        let locator = ArchiveLocator {
            version: "147.0.3".to_string(),
            channel: "release".to_string(),
            platform: "mac".to_string(),
            build_id: None,
        };
        let url = build_archive_url(&locator).unwrap();
        assert_eq!(
            url,
            "https://ftp.mozilla.org/pub/firefox/releases/147.0.3/mac/en-US/Firefox%20147.0.3.pkg"
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
    fn test_build_archive_url_beta_mac() {
        let locator = ArchiveLocator {
            version: "148.0b5".to_string(),
            channel: "beta".to_string(),
            platform: "mac".to_string(),
            build_id: None,
        };
        let url = build_archive_url(&locator).unwrap();
        assert_eq!(
            url,
            "https://ftp.mozilla.org/pub/firefox/releases/148.0b5/mac/en-US/Firefox%20148.0b5.pkg"
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
    fn test_build_archive_url_esr_mac() {
        let locator = ArchiveLocator {
            version: "128.10.0".to_string(),
            channel: "esr".to_string(),
            platform: "mac".to_string(),
            build_id: None,
        };
        let url = build_archive_url(&locator).unwrap();
        assert_eq!(
            url,
            "https://ftp.mozilla.org/pub/firefox/releases/128.10.0esr/mac/en-US/Firefox%20128.10.0esr.pkg"
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
    fn test_build_archive_url_nightly_mac() {
        let locator = ArchiveLocator {
            version: "149.0a1".to_string(),
            channel: "nightly".to_string(),
            platform: "mac".to_string(),
            build_id: Some("20250601093042".to_string()),
        };
        let url = build_archive_url(&locator).unwrap();
        assert_eq!(
            url,
            "https://ftp.mozilla.org/pub/firefox/nightly/2025/06/2025-06-01-09-30-42-mozilla-central/firefox-149.0a1.en-US.mac.pkg"
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
    fn test_archive_cache_key_mac_release() {
        let locator = ArchiveLocator {
            version: "147.0.3".to_string(),
            channel: "release".to_string(),
            platform: "mac".to_string(),
            build_id: None,
        };
        let (filename, id) = archive_cache_key(&locator).unwrap();
        assert_eq!(filename, "Firefox%20147.0.3.pkg");
        assert_eq!(id, "release-mac");
    }

    #[test]
    fn test_verify_build_id_mismatch() {
        // Minimal ELF with a build ID note — we'll test via extract + verify
        // For simplicity, just test verify_build_id returns error on non-ELF data
        let result = verify_build_id(&[0u8; 100], "abc123");
        assert!(result.is_err());
    }

    #[test]
    fn test_xar_header_too_short() {
        let result = extract_from_pkg(&[0u8; 10], "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_xar_bad_magic() {
        let mut data = vec![0u8; 100];
        data[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        let result = extract_from_pkg(&data, "test");
        assert!(result.unwrap_err().to_string().contains("not a XAR archive"));
    }

    #[test]
    fn test_extract_from_cpio() {
        // Build a minimal cpio archive (newc format)
        let mut cpio = Vec::new();

        // File entry: "some/path/XUL" with content "hello"
        let filename = b"some/path/XUL\0";
        let filedata = b"hello";
        let namesize = filename.len();
        let filesize = filedata.len();

        // cpio newc header: "070701" + 13 hex fields of 8 chars each
        let header = format!(
            "070701\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}",
            1,         // ino
            0o100644,  // mode (regular file)
            0,         // uid
            0,         // gid
            1,         // nlink
            0,         // mtime
            filesize,  // filesize
            0,         // devmajor
            0,         // devminor
            0,         // rdevmajor
            0,         // rdevminor
            namesize,  // namesize
            0,         // check
        );
        cpio.extend_from_slice(header.as_bytes());
        cpio.extend_from_slice(filename);
        // Pad to 4-byte boundary: header(110) + namesize(14) = 124, next 4-aligned = 124
        // 124 is already 4-aligned, no padding needed
        cpio.extend_from_slice(filedata);
        // Pad filedata to 4-byte boundary: 5 bytes → need 3 bytes padding
        cpio.extend_from_slice(&[0, 0, 0]);

        // Trailer entry
        let trailer_name = b"TRAILER!!!\0";
        let trailer_namesize = trailer_name.len();
        let trailer_header = format!(
            "070701\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}",
            0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, trailer_namesize, 0,
        );
        cpio.extend_from_slice(trailer_header.as_bytes());
        cpio.extend_from_slice(trailer_name);
        // Pad: header(110) + namesize(11) = 121 → next 4-aligned = 124, pad 3
        cpio.extend_from_slice(&[0, 0, 0]);

        let result = extract_from_cpio(&cpio, "XUL").unwrap();
        assert_eq!(result, b"hello");
    }

    #[test]
    fn test_extract_from_cpio_not_found() {
        // Minimal cpio with just a trailer
        let trailer_name = b"TRAILER!!!\0";
        let trailer_namesize = trailer_name.len();
        let mut cpio = Vec::new();
        let header = format!(
            "070701\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}",
            0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, trailer_namesize, 0,
        );
        cpio.extend_from_slice(header.as_bytes());
        cpio.extend_from_slice(trailer_name);
        cpio.extend_from_slice(&[0, 0, 0]);

        let result = extract_from_cpio(&cpio, "XUL");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_path_contains() {
        let path: Vec<String> = vec!["xar".into(), "toc".into(), "file".into(), "data".into()];
        assert!(path_contains(&path, "data"));
        assert!(path_contains(&path, "file"));
        assert!(!path_contains(&path, "name"));
    }
}
