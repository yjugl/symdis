// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Result, Context, bail};
use goblin::mach::constants::cputype::*;
use goblin::mach::exports::ExportInfo;
use goblin::mach::load_command::CommandVariant;
use goblin::mach::{Mach, MachO};

use super::{BinaryFile, CpuArch};

/// A parsed Mach-O file (supports fat/universal binaries).
pub struct MachOFile {
    data: Vec<u8>,
    arch: CpuArch,
    exports_list: Vec<(u64, String)>,
    /// Import address → (dylib, symbol name)
    imports_map: HashMap<u64, (String, String)>,
    segments: Vec<MachOSegment>,
}

struct MachOSegment {
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
}

impl MachOFile {
    /// Load and parse a Mach-O file from disk.
    pub fn load(path: &Path, target_arch: Option<CpuArch>) -> Result<Self> {
        let data = std::fs::read(path)
            .with_context(|| format!("reading Mach-O file: {}", path.display()))?;
        Self::from_bytes(data, target_arch)
    }

    /// Parse a Mach-O file from raw bytes.
    ///
    /// For fat (universal) binaries, `target_arch` selects which slice to use.
    /// If `None`, prefers x86_64 then arm64.
    pub fn from_bytes(data: Vec<u8>, target_arch: Option<CpuArch>) -> Result<Self> {
        match Mach::parse(&data).context("parsing Mach-O file")? {
            Mach::Binary(macho) => Self::from_macho(&data, &macho),
            Mach::Fat(multi) => {
                let target_cputype = match target_arch {
                    Some(CpuArch::X86) => Some(CPU_TYPE_X86),
                    Some(CpuArch::X86_64) => Some(CPU_TYPE_X86_64),
                    Some(CpuArch::Arm) => Some(CPU_TYPE_ARM),
                    Some(CpuArch::Arm64) => Some(CPU_TYPE_ARM64),
                    None => None,
                };

                let arches = multi.arches().context("reading fat arches")?;

                // Find matching arch
                let fat_arch = if let Some(cputype) = target_cputype {
                    arches.iter().find(|a| a.cputype == cputype)
                } else {
                    // Default: prefer x86_64, then arm64
                    arches.iter().find(|a| a.cputype == CPU_TYPE_X86_64)
                        .or_else(|| arches.iter().find(|a| a.cputype == CPU_TYPE_ARM64))
                };

                let fat_arch = fat_arch.ok_or_else(|| {
                    let available: Vec<_> = arches.iter()
                        .filter_map(|a| arch_name(a.cputype))
                        .collect();
                    anyhow::anyhow!(
                        "no matching architecture in fat binary (available: {})",
                        available.join(", ")
                    )
                })?;

                let slice = fat_arch.slice(&data);
                let macho = MachO::parse(slice, 0)
                    .context("parsing Mach-O slice from fat binary")?;
                // Use the slice, not the full fat binary — segment offsets
                // are relative to the slice start
                Self::from_macho(slice, &macho)
            }
        }
    }

    /// Build a MachOFile from a parsed MachO struct.
    fn from_macho(data: &[u8], macho: &MachO) -> Result<Self> {
        let arch = match macho.header.cputype {
            CPU_TYPE_X86 => CpuArch::X86,
            CPU_TYPE_X86_64 => CpuArch::X86_64,
            CPU_TYPE_ARM => CpuArch::Arm,
            CPU_TYPE_ARM64 => CpuArch::Arm64,
            other => bail!("unsupported Mach-O CPU type: 0x{:x}", other),
        };

        // Collect segments for VA-to-offset conversion
        let segments: Vec<MachOSegment> = macho
            .segments
            .iter()
            .map(|seg| MachOSegment {
                vmaddr: seg.vmaddr,
                vmsize: seg.vmsize,
                fileoff: seg.fileoff,
                filesize: seg.filesize,
            })
            .collect();

        // Collect exports — address is inside ExportInfo::Regular
        let mut exports_list: Vec<(u64, String)> = Vec::new();
        if let Ok(exports) = macho.exports() {
            for export in exports {
                if let ExportInfo::Regular { address, .. } = export.info {
                    if address > 0 {
                        exports_list.push((address, export.name.clone()));
                    }
                }
            }
        }
        exports_list.sort_by_key(|(addr, _)| *addr);

        // Collect imports
        let mut imports_map: HashMap<u64, (String, String)> = HashMap::new();
        if let Ok(imports) = macho.imports() {
            for import in imports {
                if import.address > 0 {
                    imports_map.insert(
                        import.address,
                        (import.dylib.to_string(), import.name.to_string()),
                    );
                }
            }
        }

        Ok(Self {
            data: data.to_vec(),
            arch,
            exports_list,
            imports_map,
            segments,
        })
    }

    /// Convert a virtual address to a file offset using segment mappings.
    pub fn va_to_offset(&self, va: u64) -> Option<u64> {
        for seg in &self.segments {
            if va >= seg.vmaddr && va < seg.vmaddr + seg.vmsize {
                let offset_in_seg = va - seg.vmaddr;
                if offset_in_seg < seg.filesize {
                    return Some(seg.fileoff + offset_in_seg);
                }
                // Address is beyond the file-backed portion
                return None;
            }
        }
        None
    }
}

/// Get a human-readable name for a CPU type constant.
fn arch_name(cputype: u32) -> Option<&'static str> {
    match cputype {
        CPU_TYPE_X86 => Some("x86"),
        CPU_TYPE_X86_64 => Some("x86_64"),
        CPU_TYPE_ARM => Some("arm"),
        CPU_TYPE_ARM64 => Some("arm64"),
        _ => None,
    }
}

/// Extract the LC_UUID from a Mach-O binary as a hex string.
///
/// For fat binaries, returns the UUIDs from all slices.
pub fn extract_macho_uuids(data: &[u8]) -> Result<Vec<String>> {
    let mut uuids = Vec::new();
    match Mach::parse(data).context("parsing Mach-O for UUID extraction")? {
        Mach::Binary(macho) => {
            if let Some(uuid) = extract_uuid_from_macho(&macho) {
                uuids.push(uuid);
            }
        }
        Mach::Fat(multi) => {
            let arches = multi.arches().context("reading fat arches")?;
            for fat_arch in &arches {
                let slice = fat_arch.slice(data);
                if let Ok(macho) = MachO::parse(slice, 0) {
                    if let Some(uuid) = extract_uuid_from_macho(&macho) {
                        uuids.push(uuid);
                    }
                }
            }
        }
    }
    Ok(uuids)
}

/// Extract LC_UUID from a single MachO binary.
fn extract_uuid_from_macho(macho: &MachO) -> Option<String> {
    for cmd in &macho.load_commands {
        if let CommandVariant::Uuid(uuid_cmd) = &cmd.command {
            let hex: String = uuid_cmd.uuid.iter().map(|b| format!("{b:02x}")).collect();
            return Some(hex);
        }
    }
    None
}

impl BinaryFile for MachOFile {
    fn arch(&self) -> CpuArch {
        self.arch
    }

    fn extract_code(&self, va: u64, size: u64) -> Result<Vec<u8>> {
        let offset = self
            .va_to_offset(va)
            .ok_or_else(|| anyhow::anyhow!("VA 0x{:x} not found in any Mach-O segment", va))?;

        let start = offset as usize;
        let end = start + size as usize;

        if end > self.data.len() {
            bail!(
                "code range 0x{:x}..0x{:x} extends beyond file (size: 0x{:x})",
                start,
                end,
                self.data.len()
            );
        }

        Ok(self.data[start..end].to_vec())
    }

    fn resolve_import(&self, va: u64) -> Option<(String, String)> {
        self.imports_map.get(&va).cloned()
    }

    fn exports(&self) -> &[(u64, String)] {
        &self.exports_list
    }

    fn build_id(&self) -> Option<String> {
        // MachOFile stores the architecture slice data, so extract_macho_uuids
        // returns exactly one UUID for this slice.
        extract_macho_uuids(&self.data)
            .ok()
            .and_then(|uuids| uuids.into_iter().next())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_macho_file() -> MachOFile {
        MachOFile {
            data: vec![0; 0x20000],
            arch: CpuArch::Arm64,
            exports_list: vec![
                (0x1000, "_main".to_string()),
                (0x2000, "_helper".to_string()),
            ],
            imports_map: HashMap::from([
                (0x5000, ("libSystem.B.dylib".to_string(), "_printf".to_string())),
            ]),
            segments: vec![
                MachOSegment {
                    vmaddr: 0x0,
                    vmsize: 0x1000,
                    fileoff: 0x0,
                    filesize: 0x0, // __PAGEZERO — no file backing
                },
                MachOSegment {
                    vmaddr: 0x1000,
                    vmsize: 0x10000,
                    fileoff: 0x0,
                    filesize: 0x10000,
                },
                MachOSegment {
                    vmaddr: 0x11000,
                    vmsize: 0x5000,
                    fileoff: 0x10000,
                    filesize: 0x3000,
                },
            ],
        }
    }

    #[test]
    fn test_arch() {
        let macho = make_macho_file();
        assert_eq!(macho.arch(), CpuArch::Arm64);
    }

    #[test]
    fn test_va_to_offset() {
        let macho = make_macho_file();

        // __PAGEZERO — zero filesize, should return None
        assert_eq!(macho.va_to_offset(0x500), None);

        // __TEXT segment (vmaddr=0x1000, fileoff=0x0)
        assert_eq!(macho.va_to_offset(0x1000), Some(0x0));
        assert_eq!(macho.va_to_offset(0x2000), Some(0x1000));
        assert_eq!(macho.va_to_offset(0x5000), Some(0x4000));

        // __DATA segment (vmaddr=0x11000, fileoff=0x10000)
        assert_eq!(macho.va_to_offset(0x11000), Some(0x10000));
        assert_eq!(macho.va_to_offset(0x12000), Some(0x11000));

        // Beyond file-backed portion of __DATA (filesize=0x3000 but vmsize=0x5000)
        assert_eq!(macho.va_to_offset(0x14000), None);

        // Not in any segment
        assert_eq!(macho.va_to_offset(0x20000), None);
    }

    #[test]
    fn test_extract_code() {
        let mut macho = make_macho_file();
        // VA 0x1000 maps to file offset 0x0 in __TEXT
        macho.data[0] = 0x55;
        macho.data[1] = 0x48;
        macho.data[2] = 0x89;
        macho.data[3] = 0xe5;

        let code = macho.extract_code(0x1000, 4).unwrap();
        assert_eq!(code, vec![0x55, 0x48, 0x89, 0xe5]);
    }

    #[test]
    fn test_extract_code_beyond_file() {
        let macho = make_macho_file();
        assert!(macho.extract_code(0x1000, 0x100000).is_err());
    }

    #[test]
    fn test_resolve_import() {
        let macho = make_macho_file();
        assert_eq!(
            macho.resolve_import(0x5000),
            Some(("libSystem.B.dylib".to_string(), "_printf".to_string()))
        );
        assert_eq!(macho.resolve_import(0x6000), None);
    }

    #[test]
    fn test_exports() {
        let macho = make_macho_file();
        let exports = macho.exports();
        assert_eq!(exports.len(), 2);
        assert_eq!(exports[0], (0x1000, "_main".to_string()));
        assert_eq!(exports[1], (0x2000, "_helper".to_string()));
    }

    #[test]
    fn test_arch_name() {
        assert_eq!(arch_name(CPU_TYPE_X86), Some("x86"));
        assert_eq!(arch_name(CPU_TYPE_X86_64), Some("x86_64"));
        assert_eq!(arch_name(CPU_TYPE_ARM), Some("arm"));
        assert_eq!(arch_name(CPU_TYPE_ARM64), Some("arm64"));
        assert_eq!(arch_name(0xFFFF), None);
    }

    #[test]
    fn test_extract_uuid_from_macho_none() {
        // A MachOFile with no UUID — just verifies the extraction function
        // doesn't panic on an empty load_commands list. Full UUID test
        // requires a real binary or synthetic Mach-O, covered in archive tests.
        let uuids = extract_macho_uuids(&[0u8; 4]);
        // Should fail to parse, which is expected
        assert!(uuids.is_err());
    }
}
