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

    /// Return the binary's build identifier (ELF build ID or Mach-O UUID).
    /// Returns `None` for formats without a build ID (e.g., PE).
    fn build_id(&self) -> Option<String> {
        None
    }

    /// Return the exact function bounds (begin_rva, end_rva) for an RVA.
    /// Uses PE .pdata entries when available. Returns `None` by default.
    fn function_bounds(&self, _rva: u64) -> Option<(u64, u64)> {
        None
    }

    /// Read a pointer-sized value at the given RVA from the on-disk binary data,
    /// and convert it from a VA to an RVA by subtracting the image base.
    /// Used to resolve intra-module function pointer tables (e.g., dispatch tables
    /// in `.rdata`). Returns `None` by default (only implemented for PE).
    fn read_pointer_at_rva(&self, _rva: u64) -> Option<u64> {
        None
    }

    /// Return the PE image base address (used to convert absolute VAs to RVAs
    /// for x86 32-bit indirect call resolution). Returns 0 by default.
    fn image_base(&self) -> u64 {
        0
    }

    /// Check whether the given RVA is in Thumb mode (ARM32 only).
    /// Returns `false` for non-ARM architectures or when no indicators are available.
    fn is_thumb(&self, _rva: u64) -> bool {
        false
    }
}
