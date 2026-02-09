// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use anyhow::{Result, bail};

/// Convert a Breakpad debug ID to a Linux ELF build ID.
///
/// The debug ID is a GUID (32 hex chars) + age (1+ hex chars).
/// The GUID's first 3 fields are byte-swapped relative to the raw build ID:
///   - Data1: 4 bytes (8 hex chars) — reverse byte order
///   - Data2: 2 bytes (4 hex chars) — reverse byte order
///   - Data3: 2 bytes (4 hex chars) — reverse byte order
///   - Data4: 8 bytes (16 hex chars) — unchanged
///
/// If the build ID was longer than 16 bytes, the extra bytes are appended
/// after the GUID portion in the debug ID (before the age digit).
/// We strip the trailing age character and reverse the byte swapping.
pub fn debug_id_to_build_id(debug_id: &str) -> Result<String> {
    // Debug ID must be at least 33 chars: 32 hex GUID + 1 age digit
    if debug_id.len() < 33 {
        bail!("debug ID too short: expected at least 33 hex chars, got {}", debug_id.len());
    }

    // Strip the last character (the age digit)
    let guid_hex = &debug_id[..debug_id.len() - 1];

    // The first 32 chars are the GUID, the rest (if any) are extra build ID bytes
    if guid_hex.len() < 32 {
        bail!("debug ID GUID portion too short");
    }
    let guid_part = &guid_hex[..32];
    let extra = &guid_hex[32..];

    // Byte-swap Data1 (chars 0..8), Data2 (chars 8..12), Data3 (chars 12..16)
    let data1 = swap_hex_bytes(&guid_part[0..8])?;
    let data2 = swap_hex_bytes(&guid_part[8..12])?;
    let data3 = swap_hex_bytes(&guid_part[12..16])?;
    let data4 = &guid_part[16..32];

    Ok(format!("{data1}{data2}{data3}{data4}{extra}").to_lowercase())
}

/// Convert a Linux ELF build ID to a Breakpad debug ID.
///
/// The build ID is a raw hex string (typically 40 chars for 20-byte SHA-1).
/// The first 16 bytes map to the GUID with byte-swapping on the first 3 fields.
/// Age is always 0 for Linux.
pub fn build_id_to_debug_id(build_id: &str) -> Result<String> {
    if build_id.len() < 32 {
        bail!("build ID too short: expected at least 32 hex chars, got {}", build_id.len());
    }

    let guid_part = &build_id[..32];
    let extra = &build_id[32..];

    // Byte-swap Data1 (chars 0..8), Data2 (chars 8..12), Data3 (chars 12..16)
    let data1 = swap_hex_bytes(&guid_part[0..8])?;
    let data2 = swap_hex_bytes(&guid_part[8..12])?;
    let data3 = swap_hex_bytes(&guid_part[12..16])?;
    let data4 = &guid_part[16..32];

    Ok(format!("{data1}{data2}{data3}{data4}{extra}0").to_uppercase())
}

/// Reverse the byte order of a hex string.
/// "b7dc60e9" → "e960dcb7"
fn swap_hex_bytes(hex: &str) -> Result<String> {
    if !hex.len().is_multiple_of(2) {
        bail!("hex string has odd length: {hex}");
    }
    let mut result = String::with_capacity(hex.len());
    for i in (0..hex.len()).rev().step_by(2) {
        result.push_str(&hex[i - 1..=i]);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_swap_hex_bytes() {
        assert_eq!(swap_hex_bytes("b7dc60e9").unwrap(), "e960dcb7");
        assert_eq!(swap_hex_bytes("1588").unwrap(), "8815");
        assert_eq!(swap_hex_bytes("d8a5").unwrap(), "a5d8");
        assert_eq!(swap_hex_bytes("AB").unwrap(), "AB");
    }

    // Test vector from SPEC.md Appendix B — Linux
    #[test]
    fn test_build_id_to_debug_id_linux() {
        let build_id = "b7dc60e91588d8a54c4c44205044422e";
        let debug_id = build_id_to_debug_id(build_id).unwrap();
        assert_eq!(debug_id, "E960DCB78815A5D84C4C44205044422E0");
    }

    #[test]
    fn test_debug_id_to_build_id_linux() {
        let debug_id = "E960DCB78815A5D84C4C44205044422E0";
        let build_id = debug_id_to_build_id(debug_id).unwrap();
        assert_eq!(build_id, "b7dc60e91588d8a54c4c44205044422e");
    }

    // Round-trip
    #[test]
    fn test_round_trip() {
        let original_build_id = "b7dc60e91588d8a54c4c44205044422e";
        let debug_id = build_id_to_debug_id(original_build_id).unwrap();
        let recovered = debug_id_to_build_id(&debug_id).unwrap();
        assert_eq!(recovered, original_build_id);
    }

    // Build ID longer than 16 bytes (20-byte SHA-1 = 40 hex chars)
    #[test]
    fn test_long_build_id() {
        let build_id = "b7dc60e91588d8a54c4c44205044422eaabbccdd";
        let debug_id = build_id_to_debug_id(build_id).unwrap();
        // Extra bytes "aabbccdd" appear before the age "0"
        assert_eq!(debug_id, "E960DCB78815A5D84C4C44205044422EAABBCCDD0");

        // Round-trip
        let recovered = debug_id_to_build_id(&debug_id).unwrap();
        assert_eq!(recovered, build_id);
    }

    #[test]
    fn test_too_short_debug_id() {
        assert!(debug_id_to_build_id("ABC").is_err());
    }

    #[test]
    fn test_too_short_build_id() {
        assert!(build_id_to_debug_id("ABC").is_err());
    }
}
