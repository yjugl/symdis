use std::collections::HashMap;
use std::path::Path;

use anyhow::{Result, Context, bail};
use goblin::pe::PE;

use super::{BinaryFile, CpuArch};

/// A parsed PE file.
pub struct PeFile {
    data: Vec<u8>,
    arch: CpuArch,
    exports_list: Vec<(u64, String)>,
    imports_map: HashMap<u64, (String, String)>,
    sections: Vec<SectionInfo>,
}

struct SectionInfo {
    virtual_address: u64,
    virtual_size: u64,
    pointer_to_raw_data: u64,
    size_of_raw_data: u64,
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
                size_of_raw_data: u64::from(s.size_of_raw_data),
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

        // Parse imports
        let mut imports_map = HashMap::new();
        for import in &pe.imports {
            let dll = import.dll.to_string();
            let name = import.name.to_string();
            let rva = import.rva as u64;
            imports_map.insert(rva, (dll, name));
        }

        Ok(Self {
            data,
            arch,
            exports_list,
            imports_map,
            sections,
        })
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rva_to_offset() {
        let pe = PeFile {
            data: vec![0; 0x10000],
            arch: CpuArch::X86_64,
            exports_list: Vec::new(),
            imports_map: HashMap::new(),
            sections: vec![
                SectionInfo {
                    virtual_address: 0x1000,
                    virtual_size: 0x5000,
                    pointer_to_raw_data: 0x400,
                    size_of_raw_data: 0x5000,
                },
                SectionInfo {
                    virtual_address: 0x7000,
                    virtual_size: 0x2000,
                    pointer_to_raw_data: 0x5400,
                    size_of_raw_data: 0x2000,
                },
            ],
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
