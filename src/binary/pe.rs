// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Result, Context, bail};
use goblin::pe::PE;

use super::{BinaryFile, CpuArch};

/// A parsed PE file.
pub struct PeFile {
    data: Vec<u8>,
    arch: CpuArch,
    image_base: u64,
    exports_list: Vec<(u64, String)>,
    imports_map: HashMap<u64, (String, String)>,
    sections: Vec<SectionInfo>,
    /// .pdata entries: (begin_rva, end_rva) pairs, sorted by begin_rva.
    /// Populated from PE exception data (x86_64 only in goblin 0.9).
    pdata_entries: Vec<(u32, u32)>,
}

struct SectionInfo {
    virtual_address: u64,
    virtual_size: u64,
    pointer_to_raw_data: u64,
}

impl PeFile {
    /// Load and parse a PE file.
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)
            .with_context(|| format!("reading PE file: {}", path.display()))?;
        Self::from_bytes(data)
    }

    /// Parse a PE file from raw bytes.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
        let pe = PE::parse(&data).context("parsing PE file")?;

        // Detect architecture
        let arch = match pe.header.coff_header.machine {
            0x014c => CpuArch::X86,
            0x8664 => CpuArch::X86_64,
            0xaa64 => CpuArch::Arm64,
            0x01c0 | 0x01c4 => CpuArch::Arm,
            other => bail!("unsupported PE machine type: 0x{:04x}", other),
        };

        // Parse sections
        let sections: Vec<SectionInfo> = pe
            .sections
            .iter()
            .map(|s| SectionInfo {
                virtual_address: u64::from(s.virtual_address),
                virtual_size: u64::from(s.virtual_size),
                pointer_to_raw_data: u64::from(s.pointer_to_raw_data),
            })
            .collect();

        // Parse exports
        let mut exports_list = Vec::new();
        for export in &pe.exports {
            if let Some(name) = &export.name {
                exports_list.push((export.rva as u64, name.to_string()));
            }
        }
        exports_list.sort_by_key(|(rva, _)| *rva);

        // Parse imports — use import.offset which is the IAT slot RVA
        // (import.rva is the Hint/Name Table RVA, not the IAT entry)
        let mut imports_map = HashMap::new();
        for import in &pe.imports {
            let dll = import.dll.to_string();
            let name = import.name.to_string();
            let iat_rva = import.offset as u64;
            imports_map.insert(iat_rva, (dll, name));
        }

        // Parse .pdata exception entries (x86_64 only in goblin 0.9)
        let mut pdata_entries = Vec::new();
        if let Some(ref exception_data) = pe.exception_data {
            for rf in exception_data.functions().flatten() {
                if rf.begin_address < rf.end_address {
                    pdata_entries.push((rf.begin_address, rf.end_address));
                }
            }
            pdata_entries.sort_unstable_by_key(|&(begin, _)| begin);
        }

        let image_base = pe.image_base as u64;

        Ok(Self {
            data,
            arch,
            image_base,
            exports_list,
            imports_map,
            sections,
            pdata_entries,
        })
    }

    /// Find the .pdata function bounds containing the given RVA.
    /// Returns (begin_rva, end_rva) if found.
    pub fn find_pdata_bounds(&self, rva: u64) -> Option<(u64, u64)> {
        let rva32 = u32::try_from(rva).ok()?;
        let idx = self.pdata_entries.partition_point(|&(begin, _)| begin <= rva32);
        if idx == 0 {
            return None;
        }
        let (begin, end) = self.pdata_entries[idx - 1];
        if rva32 < end {
            Some((u64::from(begin), u64::from(end)))
        } else {
            None
        }
    }

    /// Convert an RVA to a file offset.
    pub fn rva_to_offset(&self, rva: u64) -> Option<u64> {
        for section in &self.sections {
            if rva >= section.virtual_address
                && rva < section.virtual_address + section.virtual_size
            {
                return Some(rva - section.virtual_address + section.pointer_to_raw_data);
            }
        }
        None
    }
}

impl BinaryFile for PeFile {
    fn arch(&self) -> CpuArch {
        self.arch
    }

    fn extract_code(&self, rva: u64, size: u64) -> Result<Vec<u8>> {
        let offset = self
            .rva_to_offset(rva)
            .ok_or_else(|| anyhow::anyhow!("RVA 0x{:x} not found in any PE section", rva))?;

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

    fn resolve_import(&self, rva: u64) -> Option<(String, String)> {
        self.imports_map.get(&rva).cloned()
    }

    fn exports(&self) -> &[(u64, String)] {
        &self.exports_list
    }

    fn function_bounds(&self, rva: u64) -> Option<(u64, u64)> {
        self.find_pdata_bounds(rva)
    }

    fn read_pointer_at_rva(&self, rva: u64) -> Option<u64> {
        let offset = self.rva_to_offset(rva)? as usize;
        let ptr_size = match self.arch {
            CpuArch::X86 => 4,
            _ => 8,
        };
        if offset + ptr_size > self.data.len() {
            return None;
        }
        let value = if ptr_size == 4 {
            u64::from(u32::from_le_bytes(self.data[offset..offset + 4].try_into().ok()?))
        } else {
            u64::from_le_bytes(self.data[offset..offset + 8].try_into().ok()?)
        };
        // Convert VA to RVA by subtracting image_base
        value.checked_sub(self.image_base)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rva_to_offset() {
        let pe = PeFile {
            data: vec![0; 0x10000],
            arch: CpuArch::X86_64,
            image_base: 0x180000000,
            exports_list: Vec::new(),
            imports_map: HashMap::new(),
            sections: vec![
                SectionInfo {
                    virtual_address: 0x1000,
                    virtual_size: 0x5000,
                    pointer_to_raw_data: 0x400,
                },
                SectionInfo {
                    virtual_address: 0x7000,
                    virtual_size: 0x2000,
                    pointer_to_raw_data: 0x5400,
                },
            ],
            pdata_entries: Vec::new(),
        };

        // RVA in first section
        assert_eq!(pe.rva_to_offset(0x1000), Some(0x400));
        assert_eq!(pe.rva_to_offset(0x1500), Some(0x900));

        // RVA in second section
        assert_eq!(pe.rva_to_offset(0x7000), Some(0x5400));
        assert_eq!(pe.rva_to_offset(0x7100), Some(0x5500));

        // RVA not in any section
        assert_eq!(pe.rva_to_offset(0x500), None);
        assert_eq!(pe.rva_to_offset(0x6500), None);
    }

    #[test]
    fn test_find_pdata_bounds() {
        let pe = PeFile {
            data: vec![0; 0x10000],
            arch: CpuArch::X86_64,
            image_base: 0x180000000,
            exports_list: Vec::new(),
            imports_map: HashMap::new(),
            sections: Vec::new(),
            pdata_entries: vec![
                (0x1000, 0x1100),
                (0x2000, 0x2200),
                (0x3000, 0x3050),
            ],
        };

        // Exact start of function
        assert_eq!(pe.find_pdata_bounds(0x1000), Some((0x1000, 0x1100)));
        // Mid-function
        assert_eq!(pe.find_pdata_bounds(0x1080), Some((0x1000, 0x1100)));
        // Last byte of function
        assert_eq!(pe.find_pdata_bounds(0x10FF), Some((0x1000, 0x1100)));
        // Just past end
        assert_eq!(pe.find_pdata_bounds(0x1100), None);
        // Second function
        assert_eq!(pe.find_pdata_bounds(0x2100), Some((0x2000, 0x2200)));
        // Third function
        assert_eq!(pe.find_pdata_bounds(0x3000), Some((0x3000, 0x3050)));
        // Gap between functions
        assert_eq!(pe.find_pdata_bounds(0x1500), None);
        // Before any function
        assert_eq!(pe.find_pdata_bounds(0x500), None);
    }

    #[test]
    fn test_find_pdata_bounds_empty() {
        let pe = PeFile {
            data: Vec::new(),
            arch: CpuArch::X86_64,
            image_base: 0x180000000,
            exports_list: Vec::new(),
            imports_map: HashMap::new(),
            sections: Vec::new(),
            pdata_entries: Vec::new(),
        };
        assert_eq!(pe.find_pdata_bounds(0x1000), None);
    }

    #[test]
    fn test_read_pointer_at_rva() {
        // Build a PE with one section: VA 0x1000, raw at 0x200
        let mut data = vec![0u8; 0x1000];
        // Place an 8-byte pointer at raw offset 0x200 (= RVA 0x1000)
        // The pointer value is image_base + 0x5000 (VA → RVA 0x5000)
        let image_base: u64 = 0x180000000;
        let target_rva: u64 = 0x5000;
        let va_bytes = (image_base + target_rva).to_le_bytes();
        data[0x200..0x208].copy_from_slice(&va_bytes);

        let pe = PeFile {
            data,
            arch: CpuArch::X86_64,
            image_base,
            exports_list: Vec::new(),
            imports_map: HashMap::new(),
            sections: vec![SectionInfo {
                virtual_address: 0x1000,
                virtual_size: 0x800,
                pointer_to_raw_data: 0x200,
            }],
            pdata_entries: Vec::new(),
        };

        // RVA 0x1000 → raw 0x200 → reads pointer → subtracts image_base → RVA 0x5000
        assert_eq!(pe.read_pointer_at_rva(0x1000), Some(0x5000));

        // RVA not in any section → None
        assert_eq!(pe.read_pointer_at_rva(0x500), None);

        // RVA near end of section data → out of bounds for 8-byte read → None
        assert_eq!(pe.read_pointer_at_rva(0x17FC), None);
    }

    #[test]
    fn test_read_pointer_at_rva_x86() {
        // 32-bit PE: reads 4-byte pointer
        let mut data = vec![0u8; 0x1000];
        let image_base: u64 = 0x10000000;
        let target_rva: u64 = 0x2000;
        let va_bytes = ((image_base + target_rva) as u32).to_le_bytes();
        data[0x200..0x204].copy_from_slice(&va_bytes);

        let pe = PeFile {
            data,
            arch: CpuArch::X86,
            image_base,
            exports_list: Vec::new(),
            imports_map: HashMap::new(),
            sections: vec![SectionInfo {
                virtual_address: 0x1000,
                virtual_size: 0x800,
                pointer_to_raw_data: 0x200,
            }],
            pdata_entries: Vec::new(),
        };

        assert_eq!(pe.read_pointer_at_rva(0x1000), Some(0x2000));
    }

    #[test]
    fn test_arch_display() {
        assert_eq!(CpuArch::X86.to_string(), "x86");
        assert_eq!(CpuArch::X86_64.to_string(), "x86_64");
        assert_eq!(CpuArch::Arm.to_string(), "arm");
        assert_eq!(CpuArch::Arm64.to_string(), "arm64");
    }

    #[test]
    fn test_arch_from_sym() {
        assert_eq!(CpuArch::from_sym_arch("x86"), Some(CpuArch::X86));
        assert_eq!(CpuArch::from_sym_arch("x86_64"), Some(CpuArch::X86_64));
        assert_eq!(CpuArch::from_sym_arch("arm"), Some(CpuArch::Arm));
        assert_eq!(CpuArch::from_sym_arch("arm64"), Some(CpuArch::Arm64));
        assert_eq!(CpuArch::from_sym_arch("mips"), None);
    }
}
