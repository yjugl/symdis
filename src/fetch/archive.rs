// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::io::Read;

use anyhow::{Result, Context, bail};
use reqwest::Client;
use tracing::{info, debug};

use super::FetchResult;

const FTP_BASE: &str = "https://ftp.mozilla.org/pub/firefox";
const DEVEDITION_FTP_BASE: &str = "https://ftp.mozilla.org/pub/devedition";
const THUNDERBIRD_FTP_BASE: &str = "https://ftp.mozilla.org/pub/thunderbird";

/// Parameters needed to locate a Mozilla product build archive on the FTP server.
pub struct ArchiveLocator {
    pub product: String,
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

    if version.ends_with("esr") && locator.channel != "esr" {
        bail!(
            "version '{version}' contains 'esr' but channel is '{}' (expected 'esr')",
            locator.channel
        );
    }

    // Determine FTP base URL and filename prefix based on product
    let (ftp_base, prefix, prefix_cap) = match locator.product.as_str() {
        "firefox" => (FTP_BASE, "firefox", "Firefox"),
        "thunderbird" => (THUNDERBIRD_FTP_BASE, "thunderbird", "Thunderbird"),
        other => bail!("unknown product: {other} (expected: firefox, thunderbird)"),
    };

    match locator.channel.as_str() {
        "release" | "beta" => {
            if is_mac {
                Ok(format!(
                    "{ftp_base}/releases/{version}/{platform}/en-US/{prefix_cap}%20{version}.pkg"
                ))
            } else {
                Ok(format!(
                    "{ftp_base}/releases/{version}/{platform}/en-US/{prefix}-{version}.tar.xz"
                ))
            }
        }
        "esr" => {
            // Strip trailing "esr" if the user already included it in the version
            let ver = version.strip_suffix("esr").unwrap_or(version);
            if is_mac {
                Ok(format!(
                    "{ftp_base}/releases/{ver}esr/{platform}/en-US/{prefix_cap}%20{ver}esr.pkg"
                ))
            } else {
                Ok(format!(
                    "{ftp_base}/releases/{ver}esr/{platform}/en-US/{prefix}-{ver}esr.tar.xz"
                ))
            }
        }
        "aurora" => {
            // Firefox Developer Edition — hosted under /pub/devedition/releases/
            // Uses beta version numbering (e.g. 147.0b9).
            // macOS only has .dmg (no .pkg), so FTP extraction is Linux-only.
            if locator.product != "firefox" {
                bail!("aurora channel is only available for Firefox (Developer Edition)");
            }
            if is_mac {
                bail!(
                    "FTP archive extraction is not supported for Developer Edition on macOS \
                     (only .dmg is available, not .pkg)"
                );
            }
            Ok(format!(
                "{DEVEDITION_FTP_BASE}/releases/{version}/{platform}/en-US/firefox-{version}.tar.xz"
            ))
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
            // Thunderbird nightly: /pub/thunderbird/nightly/YYYY/MM/... with comm-central
            let tree = if locator.product == "thunderbird" { "comm-central" } else { "mozilla-central" };
            if is_mac {
                Ok(format!(
                    "{ftp_base}/nightly/{year}/{month}/{timestamp}-{tree}/{prefix}-{version}.en-US.{platform}.pkg"
                ))
            } else {
                Ok(format!(
                    "{ftp_base}/nightly/{year}/{month}/{timestamp}-{tree}/{prefix}-{version}.en-US.{platform}.tar.xz"
                ))
            }
        }
        other => bail!("unknown channel: {other} (expected: release, beta, esr, nightly, aurora)"),
    }
}

/// Extract a file from a tar.xz archive by matching the filename (ignoring directory prefix).
/// Returns the file contents as bytes.
pub fn extract_from_tar_xz(data: &[u8], target_name: &str) -> Result<Vec<u8>> {
    let decoder = liblzma::read::XzDecoder::new(data);
    extract_from_tar(decoder, target_name)
}

/// Extract a file from a tar.bz2 archive by matching the filename (ignoring directory prefix).
/// Returns the file contents as bytes.
pub fn extract_from_tar_bz2(data: &[u8], target_name: &str) -> Result<Vec<u8>> {
    let decoder = bzip2::read::BzDecoder::new(data);
    extract_from_tar(decoder, target_name)
}

/// Extract a file from a tar archive (any decompressor) by matching the filename.
fn extract_from_tar<R: Read>(reader: R, target_name: &str) -> Result<Vec<u8>> {
    let mut archive = tar::Archive::new(reader);

    let mut entry_count = 0;
    let mut last_few: Vec<String> = Vec::new();

    for entry in archive.entries().context("reading tar entries")? {
        let mut entry = entry.context("reading tar entry")?;
        let path = entry.path().context("reading entry path")?;
        let path_str = path.to_string_lossy().to_string();
        entry_count += 1;

        // Match by filename component only (ignore directory prefix like "firefox/")
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        if filename == target_name {
            debug!("found '{target_name}' at '{}' (entry #{entry_count})", path_str);
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf).context("reading tar entry contents")?;
            return Ok(buf);
        }

        // Track last few entries for diagnostic output
        if last_few.len() < 20 {
            last_few.push(path_str);
        }
    }

    debug!(
        "'{target_name}' not found in archive ({entry_count} entries). First entries: {:?}",
        last_few
    );
    bail!("file '{target_name}' not found in archive ({entry_count} entries searched)")
}

/// Extract a file from a macOS `.pkg` (XAR) archive.
///
/// PKG files are XAR archives. A simple component package has a gzip- or
/// pbzx-compressed cpio Payload at the top level. A distribution package
/// contains multiple component packages as subdirectories, each with its own
/// Payload. This function tries all Payloads found in the TOC until one
/// yields the target file.
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

    // Parse TOC XML to find all Payload file entries
    let heap_start = header_size + toc_compressed_len;
    let payloads = parse_xar_toc_for_payloads(&toc_xml)?;
    debug!("found {} Payload(s) in XAR TOC", payloads.len());

    // Try each Payload until we find the target file
    let mut last_err = None;
    for (i, &(payload_offset, payload_length)) in payloads.iter().enumerate() {
        let abs_offset = heap_start + payload_offset;
        let abs_end = abs_offset + payload_length;
        if abs_end > data.len() {
            debug!("Payload #{} extends beyond file, skipping", i);
            continue;
        }

        let payload_raw = &data[abs_offset..abs_end];
        debug!(
            "trying Payload #{} (offset={}, size={:.1} MB)",
            i,
            payload_offset,
            payload_length as f64 / 1_048_576.0
        );

        match decompress_payload(payload_raw) {
            Ok(payload) => {
                match extract_from_cpio(&payload, target_name) {
                    Ok(data) => return Ok(data),
                    Err(e) => {
                        debug!("Payload #{}: target not found in cpio: {e}", i);
                        last_err = Some(e);
                    }
                }
            }
            Err(e) => {
                debug!("Payload #{}: decompression failed: {e}", i);
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("Payload not found in XAR TOC")))
}

/// Decompress a Payload blob, detecting the compression format automatically.
///
/// Supported formats:
/// - gzip (magic `1f 8b`)
/// - XZ (magic `fd 37 7a 58 5a 00`)
/// - pbzx (magic `pbzx`) — chunked LZMA used by modern macOS PKGs
/// - raw (uncompressed cpio)
fn decompress_payload(payload_raw: &[u8]) -> Result<Vec<u8>> {
    if payload_raw.len() >= 2 && payload_raw[0] == 0x1f && payload_raw[1] == 0x8b {
        debug!("Payload compression: gzip");
        let mut buf = Vec::new();
        let mut gz = flate2::read::GzDecoder::new(payload_raw);
        gz.read_to_end(&mut buf).context("decompressing gzip Payload")?;
        Ok(buf)
    } else if payload_raw.len() >= 6 && &payload_raw[0..6] == b"\xfd7zXZ\x00" {
        debug!("Payload compression: XZ");
        let mut buf = Vec::new();
        let mut xz = liblzma::read::XzDecoder::new(payload_raw);
        xz.read_to_end(&mut buf).context("decompressing XZ Payload")?;
        Ok(buf)
    } else if payload_raw.len() >= 4 && &payload_raw[0..4] == b"pbzx" {
        debug!("Payload compression: pbzx");
        decode_pbzx(payload_raw)
    } else {
        debug!("Payload compression: none (raw)");
        Ok(payload_raw.to_vec())
    }
}

/// Decode a pbzx-compressed stream.
///
/// pbzx format:
///   magic: "pbzx" (4 bytes)
///   u64 BE: uncompressed chunk size (flags)
///   then chunks:
///     u64 BE: compressed size
///     u64 BE: uncompressed size
///     data: `compressed_size` bytes (XZ if starts with XZ magic, else raw)
fn decode_pbzx(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 12 {
        bail!("pbzx stream too short");
    }

    let mut pos = 4; // skip "pbzx"
    // Skip the flags/chunk-size u64
    pos += 8;

    let mut output = Vec::new();

    while pos + 16 <= data.len() {
        let compressed_size = u64::from_be_bytes([
            data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
            data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7],
        ]) as usize;
        let uncompressed_size = u64::from_be_bytes([
            data[pos + 8], data[pos + 9], data[pos + 10], data[pos + 11],
            data[pos + 12], data[pos + 13], data[pos + 14], data[pos + 15],
        ]) as usize;
        pos += 16;

        if compressed_size == 0 && uncompressed_size == 0 {
            break;
        }

        if pos + compressed_size > data.len() {
            bail!("pbzx chunk extends beyond stream (need {} more bytes)", pos + compressed_size - data.len());
        }

        let chunk = &data[pos..pos + compressed_size];
        pos += compressed_size;

        if chunk.len() >= 6 && &chunk[0..6] == b"\xfd7zXZ\x00" {
            let mut buf = Vec::with_capacity(uncompressed_size);
            let mut xz = liblzma::read::XzDecoder::new(chunk);
            xz.read_to_end(&mut buf).context("decompressing pbzx XZ chunk")?;
            output.extend_from_slice(&buf);
        } else {
            // Raw (uncompressed) chunk
            output.extend_from_slice(chunk);
        }
    }

    if output.is_empty() {
        bail!("pbzx produced no output");
    }

    debug!("pbzx decoded: {:.1} MB", output.len() as f64 / 1_048_576.0);
    Ok(output)
}

/// Parse XAR TOC XML to find all Payload files' heap offsets and lengths.
///
/// Returns all Payloads found (distribution PKGs may have multiple component
/// packages, each with its own Payload). They are returned in document order.
fn parse_xar_toc_for_payloads(toc_xml: &[u8]) -> Result<Vec<(usize, usize)>> {
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
    let mut payloads = Vec::new();

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

                // On </file>, check if this was a Payload file
                if tag == "file" {
                    if let Some(ctx) = file_stack.pop() {
                        if ctx.name.as_deref() == Some("Payload") {
                            if let (Some(off), Some(len)) = (ctx.data_offset, ctx.data_length) {
                                payloads.push((off, len));
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

    if payloads.is_empty() {
        bail!("Payload not found in XAR TOC");
    }

    Ok(payloads)
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
///
/// For Linux archives, tries `.tar.xz` first and falls back to `.tar.bz2`
/// on 404 (older ESR releases use bzip2 instead of xz).
pub async fn download_archive(
    client: &Client,
    locator: &ArchiveLocator,
) -> FetchResult {
    let url = match build_archive_url(locator) {
        Ok(u) => u,
        Err(e) => return FetchResult::Error(format!("building archive URL: {e}")),
    };

    let urls = if url.ends_with(".tar.xz") {
        vec![url.clone(), url.replace(".tar.xz", ".tar.bz2")]
    } else {
        vec![url]
    };

    for url in &urls {
        info!("downloading archive from {url}");

        let response = match client.get(url).send().await {
            Ok(r) => r,
            Err(e) => return FetchResult::Error(format!("request failed: {e}")),
        };

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            debug!("not found: {url}");
            continue;
        }
        if !status.is_success() {
            return FetchResult::Error(format!("HTTP {status} from {url}"));
        }

        return match response.bytes().await {
            Ok(b) => FetchResult::Ok(b.to_vec()),
            Err(e) => FetchResult::Error(format!("reading response body: {e}")),
        };
    }

    FetchResult::NotFound
}

/// Extract a binary from archive bytes, then verify its build ID.
///
/// The archive format is detected by magic bytes:
/// - XAR magic (`xar!`) → PKG (macOS)
/// - XZ magic (`\xfd7zXZ\x00`) → tar.xz
/// - bzip2 magic (`BZ`) → tar.bz2
pub fn extract_and_verify(
    archive_data: &[u8],
    binary_name: &str,
    expected_build_id: &str,
    _platform: &str,
) -> Result<Vec<u8>> {
    info!(
        "extracting {binary_name} from archive ({:.1} MB)",
        archive_data.len() as f64 / 1_048_576.0
    );

    let binary_data = if archive_data.starts_with(b"xar!") {
        extract_from_pkg(archive_data, binary_name)
            .with_context(|| format!("extracting {binary_name} from PKG"))?
    } else if archive_data.starts_with(b"\xfd7zXZ\x00") {
        extract_from_tar_xz(archive_data, binary_name)
            .with_context(|| format!("extracting {binary_name} from tar.xz"))?
    } else if archive_data.starts_with(b"BZ") {
        extract_from_tar_bz2(archive_data, binary_name)
            .with_context(|| format!("extracting {binary_name} from tar.bz2"))?
    } else {
        bail!("unrecognized archive format (expected XAR, tar.xz, or tar.bz2)")
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
            product: "firefox".to_string(),
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
            product: "firefox".to_string(),
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
            product: "firefox".to_string(),
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
            product: "firefox".to_string(),
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
            product: "firefox".to_string(),
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
            product: "firefox".to_string(),
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
    fn test_build_archive_url_esr_with_suffix() {
        // Version already contains "esr" — should not be doubled
        let locator = ArchiveLocator {
            product: "firefox".to_string(),
            version: "128.10.0esr".to_string(),
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
    fn test_build_archive_url_esr_mac_with_suffix() {
        let locator = ArchiveLocator {
            product: "firefox".to_string(),
            version: "115.32.0esr".to_string(),
            channel: "esr".to_string(),
            platform: "mac".to_string(),
            build_id: None,
        };
        let url = build_archive_url(&locator).unwrap();
        assert_eq!(
            url,
            "https://ftp.mozilla.org/pub/firefox/releases/115.32.0esr/mac/en-US/Firefox%20115.32.0esr.pkg"
        );
    }

    #[test]
    fn test_build_archive_url_nightly() {
        let locator = ArchiveLocator {
            product: "firefox".to_string(),
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
            product: "firefox".to_string(),
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
            product: "firefox".to_string(),
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
            product: "firefox".to_string(),
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
            product: "firefox".to_string(),
            version: "147.0".to_string(),
            channel: "canary".to_string(),
            platform: "linux-x86_64".to_string(),
            build_id: None,
        };
        assert!(build_archive_url(&locator).is_err());
    }

    #[test]
    fn test_build_archive_url_aurora_linux() {
        let locator = ArchiveLocator {
            product: "firefox".to_string(),
            version: "147.0b9".to_string(),
            channel: "aurora".to_string(),
            platform: "linux-x86_64".to_string(),
            build_id: None,
        };
        let url = build_archive_url(&locator).unwrap();
        assert!(url.contains("/pub/devedition/releases/"));
        assert!(url.contains("147.0b9"));
        assert!(url.ends_with(".tar.xz"));
    }

    #[test]
    fn test_build_archive_url_aurora_mac_unsupported() {
        let locator = ArchiveLocator {
            product: "firefox".to_string(),
            version: "147.0b9".to_string(),
            channel: "aurora".to_string(),
            platform: "mac".to_string(),
            build_id: None,
        };
        let err = build_archive_url(&locator).unwrap_err();
        assert!(err.to_string().contains("not supported"));
    }

    #[test]
    fn test_build_archive_url_thunderbird_release_linux() {
        let locator = ArchiveLocator {
            product: "thunderbird".to_string(),
            version: "147.0".to_string(),
            channel: "release".to_string(),
            platform: "linux-x86_64".to_string(),
            build_id: None,
        };
        let url = build_archive_url(&locator).unwrap();
        assert_eq!(
            url,
            "https://ftp.mozilla.org/pub/thunderbird/releases/147.0/linux-x86_64/en-US/thunderbird-147.0.tar.xz"
        );
    }

    #[test]
    fn test_build_archive_url_thunderbird_release_mac() {
        let locator = ArchiveLocator {
            product: "thunderbird".to_string(),
            version: "147.0".to_string(),
            channel: "release".to_string(),
            platform: "mac".to_string(),
            build_id: None,
        };
        let url = build_archive_url(&locator).unwrap();
        assert_eq!(
            url,
            "https://ftp.mozilla.org/pub/thunderbird/releases/147.0/mac/en-US/Thunderbird%20147.0.pkg"
        );
    }

    #[test]
    fn test_build_archive_url_thunderbird_esr() {
        let locator = ArchiveLocator {
            product: "thunderbird".to_string(),
            version: "140.7.1".to_string(),
            channel: "esr".to_string(),
            platform: "linux-x86_64".to_string(),
            build_id: None,
        };
        let url = build_archive_url(&locator).unwrap();
        assert_eq!(
            url,
            "https://ftp.mozilla.org/pub/thunderbird/releases/140.7.1esr/linux-x86_64/en-US/thunderbird-140.7.1esr.tar.xz"
        );
    }

    #[test]
    fn test_build_archive_url_thunderbird_aurora_rejected() {
        let locator = ArchiveLocator {
            product: "thunderbird".to_string(),
            version: "147.0b9".to_string(),
            channel: "aurora".to_string(),
            platform: "linux-x86_64".to_string(),
            build_id: None,
        };
        let err = build_archive_url(&locator).unwrap_err();
        assert!(err.to_string().contains("only available for Firefox"));
    }

    #[test]
    fn test_build_archive_url_esr_version_wrong_channel() {
        let locator = ArchiveLocator {
            product: "firefox".to_string(),
            version: "128.10.0esr".to_string(),
            channel: "release".to_string(),
            platform: "linux-x86_64".to_string(),
            build_id: None,
        };
        let err = build_archive_url(&locator).unwrap_err();
        assert!(err.to_string().contains("expected 'esr'"));
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
            product: "firefox".to_string(),
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
            product: "firefox".to_string(),
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
            product: "firefox".to_string(),
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

    #[test]
    fn test_parse_xar_toc_single_payload() {
        let toc = br#"<?xml version="1.0" encoding="UTF-8"?>
<xar>
  <toc>
    <file>
      <data><offset>0</offset><length>1000</length></data>
      <name>Payload</name>
    </file>
  </toc>
</xar>"#;
        let payloads = parse_xar_toc_for_payloads(toc).unwrap();
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0], (0, 1000));
    }

    #[test]
    fn test_parse_xar_toc_multiple_payloads() {
        // Distribution PKG with two component packages, each containing a Payload
        let toc = br#"<?xml version="1.0" encoding="UTF-8"?>
<xar>
  <toc>
    <file>
      <data><offset>0</offset><length>100</length></data>
      <name>Distribution</name>
    </file>
    <file>
      <name>org.mozilla.firefox.pkg</name>
      <data><offset>100</offset><length>50</length></data>
      <file>
        <data><offset>200</offset><length>5000</length></data>
        <name>Payload</name>
      </file>
      <file>
        <data><offset>5200</offset><length>100</length></data>
        <name>Bom</name>
      </file>
    </file>
    <file>
      <name>org.mozilla.helper.pkg</name>
      <data><offset>6000</offset><length>30</length></data>
      <file>
        <data><offset>6100</offset><length>2000</length></data>
        <name>Payload</name>
      </file>
    </file>
  </toc>
</xar>"#;
        let payloads = parse_xar_toc_for_payloads(toc).unwrap();
        assert_eq!(payloads.len(), 2);
        assert_eq!(payloads[0], (200, 5000));
        assert_eq!(payloads[1], (6100, 2000));
    }

    #[test]
    fn test_parse_xar_toc_no_payload() {
        let toc = br#"<?xml version="1.0" encoding="UTF-8"?>
<xar>
  <toc>
    <file>
      <data><offset>0</offset><length>100</length></data>
      <name>SomeOtherFile</name>
    </file>
  </toc>
</xar>"#;
        let result = parse_xar_toc_for_payloads(toc);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Payload not found"));
    }

    #[test]
    fn test_decompress_payload_raw() {
        let raw = b"070701"; // cpio magic-ish
        let result = decompress_payload(raw).unwrap();
        assert_eq!(result, raw);
    }

    #[test]
    fn test_decompress_payload_gzip() {
        // Create a gzip-compressed payload
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let original = b"test data for gzip compression";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let result = decompress_payload(&compressed).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn test_decode_pbzx_empty() {
        let result = decode_pbzx(b"pbz");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_binary_id_non_elf_strict() {
        // Non-ELF data should fail verification
        let result = verify_binary_id(&[0u8; 100], "abc123");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_binary_id_elf_mismatch() {
        // Construct a minimal ELF with a build ID that doesn't match
        let elf_data = build_elf_with_build_id(b"\xaa\xbb\xcc\xdd");
        let result = verify_binary_id(&elf_data, "11223344");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("mismatch"));
    }

    #[test]
    fn test_verify_binary_id_elf_match() {
        let elf_data = build_elf_with_build_id(b"\xaa\xbb\xcc\xdd");
        let result = verify_binary_id(&elf_data, "aabbccdd");
        assert!(result.is_ok());
    }

    /// Helper: build a minimal 64-bit little-endian ELF with a .note.gnu.build-id section.
    fn build_elf_with_build_id(id_bytes: &[u8]) -> Vec<u8> {
        // ELF64 header (64 bytes) + section header string table + .note.gnu.build-id + section headers
        let mut buf = Vec::new();

        // -- ELF header (64 bytes) --
        buf.extend_from_slice(&[0x7f, b'E', b'L', b'F']); // e_ident magic
        buf.push(2); // EI_CLASS = ELFCLASS64
        buf.push(1); // EI_DATA = ELFDATA2LSB
        buf.push(1); // EI_VERSION
        buf.extend_from_slice(&[0; 9]); // padding
        buf.extend_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
        buf.extend_from_slice(&0x3eu16.to_le_bytes()); // e_machine = EM_X86_64
        buf.extend_from_slice(&1u32.to_le_bytes()); // e_version
        buf.extend_from_slice(&0u64.to_le_bytes()); // e_entry
        buf.extend_from_slice(&0u64.to_le_bytes()); // e_phoff
        // e_shoff: section headers at end (we'll fill this in)
        let shoff_pos = buf.len();
        buf.extend_from_slice(&0u64.to_le_bytes()); // placeholder
        buf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        buf.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
        buf.extend_from_slice(&0u16.to_le_bytes()); // e_phentsize
        buf.extend_from_slice(&0u16.to_le_bytes()); // e_phnum
        buf.extend_from_slice(&64u16.to_le_bytes()); // e_shentsize
        buf.extend_from_slice(&3u16.to_le_bytes()); // e_shnum (null + shstrtab + note)
        buf.extend_from_slice(&1u16.to_le_bytes()); // e_shstrndx = 1
        assert_eq!(buf.len(), 64);

        // -- Section data --

        // Section header string table (section 1)
        let shstrtab_offset = buf.len();
        // Index 0: null byte
        // Index 1: ".shstrtab\0"
        // Index 11: ".note.gnu.build-id\0"
        let shstrtab = b"\0.shstrtab\0.note.gnu.build-id\0";
        buf.extend_from_slice(shstrtab);

        // .note.gnu.build-id data (section 2)
        let note_offset = buf.len();
        let namesz = 4u32; // "GNU\0"
        let descsz = id_bytes.len() as u32;
        buf.extend_from_slice(&namesz.to_le_bytes());
        buf.extend_from_slice(&descsz.to_le_bytes());
        buf.extend_from_slice(&3u32.to_le_bytes()); // NT_GNU_BUILD_ID
        buf.extend_from_slice(b"GNU\0");
        buf.extend_from_slice(id_bytes);
        let note_size = buf.len() - note_offset;

        // Align to 8 bytes for section headers
        while buf.len() % 8 != 0 {
            buf.push(0);
        }

        // -- Section headers --
        let shoff = buf.len();

        // Section 0: null
        buf.extend_from_slice(&[0u8; 64]);

        // Section 1: .shstrtab
        buf.extend_from_slice(&1u32.to_le_bytes()); // sh_name (index into shstrtab)
        buf.extend_from_slice(&3u32.to_le_bytes()); // sh_type = SHT_STRTAB
        buf.extend_from_slice(&0u64.to_le_bytes()); // sh_flags
        buf.extend_from_slice(&0u64.to_le_bytes()); // sh_addr
        buf.extend_from_slice(&(shstrtab_offset as u64).to_le_bytes()); // sh_offset
        buf.extend_from_slice(&(shstrtab.len() as u64).to_le_bytes()); // sh_size
        buf.extend_from_slice(&0u32.to_le_bytes()); // sh_link
        buf.extend_from_slice(&0u32.to_le_bytes()); // sh_info
        buf.extend_from_slice(&1u64.to_le_bytes()); // sh_addralign
        buf.extend_from_slice(&0u64.to_le_bytes()); // sh_entsize

        // Section 2: .note.gnu.build-id
        buf.extend_from_slice(&11u32.to_le_bytes()); // sh_name (index 11 in shstrtab)
        buf.extend_from_slice(&7u32.to_le_bytes()); // sh_type = SHT_NOTE
        buf.extend_from_slice(&0u64.to_le_bytes()); // sh_flags
        buf.extend_from_slice(&0u64.to_le_bytes()); // sh_addr
        buf.extend_from_slice(&(note_offset as u64).to_le_bytes()); // sh_offset
        buf.extend_from_slice(&(note_size as u64).to_le_bytes()); // sh_size
        buf.extend_from_slice(&0u32.to_le_bytes()); // sh_link
        buf.extend_from_slice(&0u32.to_le_bytes()); // sh_info
        buf.extend_from_slice(&4u64.to_le_bytes()); // sh_addralign
        buf.extend_from_slice(&0u64.to_le_bytes()); // sh_entsize

        // Patch e_shoff
        let shoff_bytes = (shoff as u64).to_le_bytes();
        buf[shoff_pos..shoff_pos + 8].copy_from_slice(&shoff_bytes);

        buf
    }
}
