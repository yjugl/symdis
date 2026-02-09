// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

pub mod elf;
pub mod macho;
pub mod pe;

use anyhow::Result;

/// CPU architecture enum shared across the codebase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuArch {
    X86,
    X86_64,
    Arm,
    Arm64,
}

impl CpuArch {
    /// Parse from a .sym MODULE record's arch field.
    pub fn from_sym_arch(arch: &str) -> Option<Self> {
        match arch {
            "x86" => Some(Self::X86),
            "x86_64" => Some(Self::X86_64),
            "arm" => Some(Self::Arm),
            "arm64" => Some(Self::Arm64),
            _ => None,
        }
    }
}

impl std::fmt::Display for CpuArch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::X86 => write!(f, "x86"),
            Self::X86_64 => write!(f, "x86_64"),
            Self::Arm => write!(f, "arm"),
            Self::Arm64 => write!(f, "arm64"),
        }
    }
}

/// Trait for accessing binary file contents.
pub trait BinaryFile {
    /// Get the CPU architecture.
    fn arch(&self) -> CpuArch;

    /// Extract code bytes at the given RVA with the given size.
    fn extract_code(&self, rva: u64, size: u64) -> Result<Vec<u8>>;

    /// Resolve an import table entry by RVA.
    fn resolve_import(&self, rva: u64) -> Option<(String, String)>;

    /// Get all exports as (rva, name) pairs.
    fn exports(&self) -> &[(u64, String)];
}
