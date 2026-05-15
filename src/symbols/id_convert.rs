// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use anyhow::{Result, bail};

/// Format 16 raw GUID bytes as the 32-char uppercase hex prefix of a
/// Breakpad debug ID.
///
/// The bytes are interpreted as a Windows GUID stored in little-endian
/// (Data1 = 4 LE bytes, Data2 = 2 LE bytes, Data3 = 2 LE bytes, Data4 =
/// 8 raw bytes). The Breakpad display reverses Data1/2/3 to big-endian
/// while leaving Data4 untouched.
///
/// Callers append the age separately:
///   - ELF / Mach-O: always `"0"`.
///   - PE: `format!("{:X}", age)` from the CodeView CV_INFO_PDB70 record.
///
/// Never apply this swap to a Mach-O LC_UUID -- those bytes are already
/// in natural UUID byte order and need no transformation.
pub(crate) fn format_breakpad_guid(bytes: &[u8; 16]) -> String {
    let mut out = String::with_capacity(32);
    // Data1 -- 4 bytes LE -> BE
    for b in bytes[0..4].iter().rev() {
        out.push_str(&format!("{b:02X}"));
    }
    // Data2 -- 2 bytes LE -> BE
    for b in bytes[4..6].iter().rev() {
        out.push_str(&format!("{b:02X}"));
    }
    // Data3 -- 2 bytes LE -> BE
    for b in bytes[6..8].iter().rev() {
        out.push_str(&format!("{b:02X}"));
    }
    // Data4 -- 8 bytes unchanged
    for b in &bytes[8..16] {
        out.push_str(&format!("{b:02X}"));
    }
    out
}

/// Convert a Linux ELF build ID to a standard Breakpad debug ID (33 chars).
///
/// The build ID is a raw hex string (typically 40 chars for 20-byte SHA-1).
/// Only the first 16 bytes are used for the GUID, treated as a little-endian
/// Windows GUID and byte-swapped via [`format_breakpad_guid`]. Any bytes
/// beyond the first 16 are discarded (Breakpad does the same). Age is
/// always 0 for Linux.
pub fn build_id_to_debug_id(build_id: &str) -> Result<String> {
    if build_id.len() < 32 {
        bail!(
            "build ID too short: expected at least 32 hex chars, got {}",
            build_id.len()
        );
    }

    let mut guid = [0u8; 16];
    for (i, chunk) in guid.iter_mut().enumerate() {
        let hex = &build_id[i * 2..i * 2 + 2];
        *chunk = u8::from_str_radix(hex, 16)
            .map_err(|_| anyhow::anyhow!("invalid hex in build ID at byte {i}: {hex}"))?;
    }

    Ok(format!("{}0", format_breakpad_guid(&guid)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // 16-byte build ID (32 hex chars)
    #[test]
    fn test_build_id_to_debug_id_16_bytes() {
        let build_id = "b7dc60e91588d8a54c4c44205044422e";
        let debug_id = build_id_to_debug_id(build_id).unwrap();
        assert_eq!(debug_id, "E960DCB78815A5D84C4C44205044422E0");
    }

    // 20-byte build ID (40 hex chars, SHA-1 — the common case)
    // Extra bytes beyond 16 are discarded, matching Breakpad's behavior.
    #[test]
    fn test_build_id_to_debug_id_20_bytes() {
        let build_id = "b7dc60e91588d8a54c4c44205044422eaabbccdd";
        let debug_id = build_id_to_debug_id(build_id).unwrap();
        assert_eq!(debug_id, "E960DCB78815A5D84C4C44205044422E0");
    }

    #[test]
    fn test_too_short_build_id() {
        assert!(build_id_to_debug_id("ABC").is_err());
    }

    #[test]
    fn test_invalid_hex_build_id() {
        // Length is fine but contains non-hex; must error rather than panic.
        let result = build_id_to_debug_id("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");
        assert!(result.is_err());
    }

    #[test]
    fn test_format_breakpad_guid_swaps_data1_2_3_only() {
        let bytes: [u8; 16] = [
            0xb7, 0xdc, 0x60, 0xe9, // Data1 LE -> "E960DCB7"
            0x15, 0x88, // Data2 LE -> "8815"
            0xd8, 0xa5, // Data3 LE -> "A5D8"
            0x4c, 0x4c, 0x44, 0x20, 0x50, 0x44, 0x42, 0x2e, // Data4 unchanged
        ];
        assert_eq!(
            format_breakpad_guid(&bytes),
            "E960DCB78815A5D84C4C44205044422E"
        );
    }
}
