// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use anyhow::{Result, bail};

/// Convert a Linux ELF build ID to a standard Breakpad debug ID (33 chars).
///
/// The build ID is a raw hex string (typically 40 chars for 20-byte SHA-1).
/// Only the first 16 bytes are used for the GUID, with byte-swapping on
/// the first 3 fields:
///   - Data1: 4 bytes (8 hex chars) — reverse byte order
///   - Data2: 2 bytes (4 hex chars) — reverse byte order
///   - Data3: 2 bytes (4 hex chars) — reverse byte order
///   - Data4: 8 bytes (16 hex chars) — unchanged
///
/// Any bytes beyond the first 16 are discarded (Breakpad does the same).
/// Age is always 0 for Linux.
pub fn build_id_to_debug_id(build_id: &str) -> Result<String> {
    if build_id.len() < 32 {
        bail!("build ID too short: expected at least 32 hex chars, got {}", build_id.len());
    }

    let guid_part = &build_id[..32];

    // Byte-swap Data1 (chars 0..8), Data2 (chars 8..12), Data3 (chars 12..16)
    let data1 = swap_hex_bytes(&guid_part[0..8])?;
    let data2 = swap_hex_bytes(&guid_part[8..12])?;
    let data3 = swap_hex_bytes(&guid_part[12..16])?;
    let data4 = &guid_part[16..32];

    Ok(format!("{data1}{data2}{data3}{data4}0").to_uppercase())
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
}
