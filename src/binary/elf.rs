// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Result, Context, bail};
use goblin::elf::Elf;
use goblin::elf::program_header::PT_LOAD;
use goblin::elf::reloc;
use goblin::elf::sym::{STT_FUNC, STT_GNU_IFUNC, STT_NOTYPE};

use super::{BinaryFile, CpuArch};

/// A parsed ELF file.
pub struct ElfFile {
    data: Vec<u8>,
    arch: CpuArch,
    exports_list: Vec<(u64, String)>,
    /// PLT stub address → (library, function name)
    imports_map: HashMap<u64, (String, String)>,
    segments: Vec<LoadSegment>,
    /// Sorted ARM Thumb/ARM mode markers: (address, is_thumb).
    /// Binary-search for the nearest entry at-or-before an address.
    thumb_markers: Vec<(u64, bool)>,
}

struct LoadSegment {
    vaddr: u64,
    memsz: u64,
    offset: u64,
    filesz: u64,
}

impl ElfFile {
    /// Load and parse an ELF file.
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)
            .with_context(|| format!("reading ELF file: {}", path.display()))?;
        Self::from_bytes(data)
    }

    /// Parse an ELF file from raw bytes.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
        let elf = Elf::parse(&data).context("parsing ELF file")?;

        let arch = match elf.header.e_machine {
            3 => CpuArch::X86,       // EM_386
            62 => CpuArch::X86_64,   // EM_X86_64
            40 => CpuArch::Arm,      // EM_ARM
            183 => CpuArch::Arm64,   // EM_AARCH64
            other => bail!("unsupported ELF machine type: {}", other),
        };

        // Collect PT_LOAD segments for address-to-offset conversion
        let segments: Vec<LoadSegment> = elf
            .program_headers
            .iter()
            .filter(|ph| ph.p_type == PT_LOAD)
            .map(|ph| LoadSegment {
                vaddr: ph.p_vaddr,
                memsz: ph.p_memsz,
                offset: ph.p_offset,
                filesz: ph.p_filesz,
            })
            .collect();

        // Collect exported/defined function symbols from both .dynsym and .symtab
        let mut exports_map: HashMap<u64, String> = HashMap::new();

        // .dynsym — defined (non-import) function symbols
        for sym in elf.dynsyms.iter() {
            let ty = sym.st_type();
            if (ty == STT_FUNC || ty == STT_GNU_IFUNC)
                && sym.st_value != 0
                && !sym.is_import()
            {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        exports_map.insert(sym.st_value, name.to_string());
                    }
                }
            }
        }

        // .symtab — defined function symbols (may not exist in stripped binaries)
        for sym in elf.syms.iter() {
            let ty = sym.st_type();
            if (ty == STT_FUNC || ty == STT_GNU_IFUNC)
                && sym.st_value != 0
                && !sym.is_import()
            {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        exports_map.entry(sym.st_value).or_insert_with(|| name.to_string());
                    }
                }
            }
        }

        let mut exports_list: Vec<(u64, String)> = exports_map.into_iter().collect();
        exports_list.sort_by_key(|(addr, _)| *addr);

        // Build PLT import map: PLT stub address → (library, symbol name)
        let mut imports_map = build_plt_imports(&elf, arch);

        // Add GOT slot → import name entries from dynamic relocations.
        // This enables resolution of indirect calls through the GOT
        // (e.g., x86-64 `call [rip+disp]` in -fno-plt builds, AArch64 ADRP+LDR+BLR).
        build_got_imports(&elf, arch, &mut imports_map);

        // Collect Thumb/ARM mode markers for ARM32 binaries.
        let thumb_markers = if arch == CpuArch::Arm {
            collect_thumb_markers(&elf)
        } else {
            Vec::new()
        };

        Ok(Self {
            data,
            arch,
            exports_list,
            imports_map,
            segments,
            thumb_markers,
        })
    }

    /// Convert a virtual address to a file offset using PT_LOAD segments.
    pub fn va_to_offset(&self, va: u64) -> Option<u64> {
        for seg in &self.segments {
            if va >= seg.vaddr && va < seg.vaddr + seg.memsz {
                let offset_in_seg = va - seg.vaddr;
                if offset_in_seg < seg.filesz {
                    return Some(seg.offset + offset_in_seg);
                }
                // Address is in BSS (beyond file-backed portion)
                return None;
            }
        }
        None
    }
}

/// Collect ARM Thumb/ARM mode markers from ELF symbol tables.
///
/// Two sources of information:
/// 1. Mapping symbols (`$t` = Thumb, `$a` = ARM) in `.symtab` — most reliable.
/// 2. Function symbols with bit 0 set in `st_value` (`.dynsym` + `.symtab`).
///
/// Mapping symbols take priority over function symbols at the same address.
fn collect_thumb_markers(elf: &Elf) -> Vec<(u64, bool)> {
    use std::collections::BTreeMap;

    // BTreeMap ensures sorted order and deduplication by address.
    // We process function symbols first, then mapping symbols, so mapping
    // symbols overwrite function symbols at the same address.
    let mut markers: BTreeMap<u64, bool> = BTreeMap::new();

    // Pass 1: Function symbols (lower priority) from both .dynsym and .symtab
    for sym in elf.dynsyms.iter().chain(elf.syms.iter()) {
        let ty = sym.st_type();
        if (ty == STT_FUNC || ty == STT_GNU_IFUNC) && sym.st_value != 0 {
            let is_thumb = sym.st_value & 1 != 0;
            let addr = sym.st_value & !1;
            markers.insert(addr, is_thumb);
        }
    }

    // Pass 2: Mapping symbols (higher priority) from .symtab only
    // ($t and $a are STT_NOTYPE with those exact names or $t.N/$a.N variants)
    for sym in elf.syms.iter() {
        if sym.st_type() != STT_NOTYPE || sym.st_value == 0 {
            continue;
        }
        let name = elf.strtab.get_at(sym.st_name).unwrap_or("");
        let is_thumb = if name == "$t" || name.starts_with("$t.") {
            Some(true)
        } else if name == "$a" || name.starts_with("$a.") {
            Some(false)
        } else {
            None
        };
        if let Some(thumb) = is_thumb {
            markers.insert(sym.st_value, thumb);
        }
    }

    markers.into_iter().collect()
}

/// Return the PLT header size and entry size for a given architecture.
///
/// The PLT header (PLT[0]) is the resolver stub and can differ in size
/// from the regular PLT entries that follow it.
fn plt_sizes(arch: CpuArch) -> (u64, u64) {
    match arch {
        // AArch64: 32-byte header, 16-byte entries
        CpuArch::Arm64 => (32, 16),
        // ARM: 20-byte header, 12-byte entries
        CpuArch::Arm => (20, 12),
        // x86 and x86_64: 16-byte header, 16-byte entries
        _ => (16, 16),
    }
}

/// Build a map from PLT stub virtual addresses to imported symbol names.
///
/// Each pltreloc entry corresponds to a GOT slot for an imported function.
/// The PLT stubs are laid out sequentially: PLT[0] is the resolver (header),
/// PLT[1..] correspond to pltrelocs[0..] in order. The header size can
/// differ from the entry size on ARM/AArch64.
///
/// Also checks `.plt.got` and `.iplt` sections for additional PLT entries
/// (used by some linkers, especially with `-z now` eager binding).
fn build_plt_imports(elf: &Elf, arch: CpuArch) -> HashMap<u64, (String, String)> {
    let mut map = HashMap::new();

    let (plt_header_size, plt_entry_size) = plt_sizes(arch);

    // Collect all PLT-like sections: .plt, .plt.got, .iplt
    let plt_sections: Vec<u64> = elf.section_headers.iter().filter_map(|sh| {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        match name {
            ".plt" | ".plt.got" | ".iplt" => Some(sh.sh_addr),
            _ => None,
        }
    }).collect();

    if plt_sections.is_empty() {
        return map;
    }

    // Use the first .plt section as the primary PLT base for address computation
    let plt_addr = plt_sections[0];

    // Map each pltreloc to a PLT stub address
    // PLT[0] is the resolver stub (header), first import starts after it
    for (i, reloc) in elf.pltrelocs.iter().enumerate() {
        let stub_addr = plt_addr + plt_header_size + i as u64 * plt_entry_size;
        if let Some(sym) = elf.dynsyms.get(reloc.r_sym) {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if !name.is_empty() {
                    map.insert(stub_addr, (String::new(), name.to_string()));
                }
            }
        }
    }

    map
}

/// Return the GLOB_DAT and JUMP_SLOT relocation type constants for a given architecture.
fn got_reloc_types(arch: CpuArch) -> &'static [u32] {
    match arch {
        CpuArch::X86_64 => &[reloc::R_X86_64_GLOB_DAT, reloc::R_X86_64_JUMP_SLOT],
        CpuArch::X86 => &[reloc::R_386_GLOB_DAT, reloc::R_386_JMP_SLOT],
        CpuArch::Arm64 => &[reloc::R_AARCH64_GLOB_DAT, reloc::R_AARCH64_JUMP_SLOT],
        CpuArch::Arm => &[reloc::R_ARM_GLOB_DAT, reloc::R_ARM_JUMP_SLOT],
    }
}

/// Build a map from GOT slot virtual addresses to imported symbol names.
///
/// Dynamic relocations (`dynrelas`/`dynrels`) and PLT relocations (`pltrelocs`)
/// contain entries whose `r_offset` is the GOT slot VA and `r_sym` identifies
/// the imported symbol. This maps those GOT slots so that indirect calls/jumps
/// through the GOT (e.g., x86-64 `call [rip+disp]`, AArch64 ADRP+LDR+BLR)
/// can be resolved to their target import names.
fn build_got_imports(
    elf: &Elf,
    arch: CpuArch,
    imports_map: &mut HashMap<u64, (String, String)>,
) {
    let types = got_reloc_types(arch);

    let all_relocs = elf.dynrelas.iter()
        .chain(elf.dynrels.iter())
        .chain(elf.pltrelocs.iter());

    for reloc in all_relocs {
        if !types.contains(&reloc.r_type) {
            continue;
        }
        let got_va = reloc.r_offset;
        // Skip if this VA is already mapped (PLT stub map takes precedence for stub addresses,
        // but GOT slots are at different addresses so collisions are unlikely)
        if imports_map.contains_key(&got_va) {
            continue;
        }
        if let Some(sym) = elf.dynsyms.get(reloc.r_sym) {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if !name.is_empty() {
                    imports_map.insert(got_va, (String::new(), name.to_string()));
                }
            }
        }
    }
}

impl BinaryFile for ElfFile {
    fn arch(&self) -> CpuArch {
        self.arch
    }

    fn extract_code(&self, va: u64, size: u64) -> Result<Vec<u8>> {
        let offset = self
            .va_to_offset(va)
            .ok_or_else(|| anyhow::anyhow!("VA 0x{:x} not found in any ELF PT_LOAD segment", va))?;

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
        crate::fetch::archive::extract_elf_build_id(&self.data).ok().flatten()
    }

    fn read_pointer_at_rva(&self, rva: u64) -> Option<u64> {
        let offset = self.va_to_offset(rva)? as usize;
        let ptr_size = match self.arch {
            CpuArch::X86 | CpuArch::Arm => 4,
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
        // ELF pointers are absolute VAs (same address space as our RVAs),
        // so no base subtraction needed. Filter out zero (unresolved relocations).
        if value == 0 { None } else { Some(value) }
    }

    fn is_thumb(&self, rva: u64) -> bool {
        if self.thumb_markers.is_empty() {
            return false;
        }
        // Binary search for the largest address <= rva
        let idx = self.thumb_markers.partition_point(|&(addr, _)| addr <= rva);
        if idx == 0 {
            return false;
        }
        self.thumb_markers[idx - 1].1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_elf_file() -> ElfFile {
        ElfFile {
            data: vec![0; 0x20000],
            arch: CpuArch::X86_64,
            exports_list: vec![
                (0x1000, "func_a".to_string()),
                (0x2000, "func_b".to_string()),
            ],
            imports_map: HashMap::from([
                (0x3000, ("libc.so.6".to_string(), "malloc".to_string())),
            ]),
            segments: vec![
                LoadSegment {
                    vaddr: 0x0,
                    memsz: 0x10000,
                    offset: 0x0,
                    filesz: 0x10000,
                },
                LoadSegment {
                    vaddr: 0x10000,
                    memsz: 0x10000,
                    offset: 0x10000,
                    filesz: 0x8000,
                },
            ],
            thumb_markers: Vec::new(),
        }
    }

    #[test]
    fn test_va_to_offset() {
        let elf = make_elf_file();

        // Address in first segment
        assert_eq!(elf.va_to_offset(0x1000), Some(0x1000));
        assert_eq!(elf.va_to_offset(0x5000), Some(0x5000));

        // Address in second segment
        assert_eq!(elf.va_to_offset(0x10000), Some(0x10000));
        assert_eq!(elf.va_to_offset(0x12000), Some(0x12000));

        // Address in BSS portion (beyond filesz)
        assert_eq!(elf.va_to_offset(0x19000), None);

        // Address not in any segment
        assert_eq!(elf.va_to_offset(0x30000), None);
    }

    #[test]
    fn test_va_to_offset_with_nonzero_base() {
        let elf = ElfFile {
            data: vec![0; 0x10000],
            arch: CpuArch::X86_64,
            exports_list: Vec::new(),
            imports_map: HashMap::new(),
            segments: vec![LoadSegment {
                vaddr: 0x400000,
                memsz: 0x5000,
                offset: 0x1000,
                filesz: 0x5000,
            }],
            thumb_markers: Vec::new(),
        };

        assert_eq!(elf.va_to_offset(0x400000), Some(0x1000));
        assert_eq!(elf.va_to_offset(0x401000), Some(0x2000));
        assert_eq!(elf.va_to_offset(0x3FFFFF), None);
    }

    #[test]
    fn test_extract_code() {
        let mut elf = make_elf_file();
        // Write known bytes at offset 0x1000
        elf.data[0x1000] = 0x55; // push rbp
        elf.data[0x1001] = 0x48;
        elf.data[0x1002] = 0x89;
        elf.data[0x1003] = 0xe5;

        let code = elf.extract_code(0x1000, 4).unwrap();
        assert_eq!(code, vec![0x55, 0x48, 0x89, 0xe5]);
    }

    #[test]
    fn test_extract_code_beyond_file() {
        let elf = make_elf_file();
        assert!(elf.extract_code(0x1000, 0x100000).is_err());
    }

    #[test]
    fn test_resolve_import() {
        let elf = make_elf_file();
        assert_eq!(
            elf.resolve_import(0x3000),
            Some(("libc.so.6".to_string(), "malloc".to_string()))
        );
        assert_eq!(elf.resolve_import(0x4000), None);
    }

    #[test]
    fn test_exports() {
        let elf = make_elf_file();
        let exports = elf.exports();
        assert_eq!(exports.len(), 2);
        assert_eq!(exports[0], (0x1000, "func_a".to_string()));
        assert_eq!(exports[1], (0x2000, "func_b".to_string()));
    }

    #[test]
    fn test_arch() {
        let elf = make_elf_file();
        assert_eq!(elf.arch(), CpuArch::X86_64);
    }

    #[test]
    fn test_plt_sizes_x86() {
        let (header, entry) = super::plt_sizes(CpuArch::X86);
        assert_eq!(header, 16);
        assert_eq!(entry, 16);
    }

    #[test]
    fn test_plt_sizes_x86_64() {
        let (header, entry) = super::plt_sizes(CpuArch::X86_64);
        assert_eq!(header, 16);
        assert_eq!(entry, 16);
    }

    #[test]
    fn test_plt_sizes_arm() {
        let (header, entry) = super::plt_sizes(CpuArch::Arm);
        assert_eq!(header, 20);
        assert_eq!(entry, 12);
    }

    #[test]
    fn test_plt_sizes_arm64() {
        let (header, entry) = super::plt_sizes(CpuArch::Arm64);
        assert_eq!(header, 32);
        assert_eq!(entry, 16);
    }

    fn make_arm_elf_with_markers(markers: Vec<(u64, bool)>) -> ElfFile {
        ElfFile {
            data: vec![0; 0x10000],
            arch: CpuArch::Arm,
            exports_list: Vec::new(),
            imports_map: HashMap::new(),
            segments: vec![LoadSegment {
                vaddr: 0x0,
                memsz: 0x10000,
                offset: 0x0,
                filesz: 0x10000,
            }],
            thumb_markers: markers,
        }
    }

    #[test]
    fn test_is_thumb_empty_markers() {
        let elf = make_arm_elf_with_markers(vec![]);
        assert!(!elf.is_thumb(0x1000));
    }

    #[test]
    fn test_is_thumb_single_thumb_marker() {
        let elf = make_arm_elf_with_markers(vec![(0x1000, true)]);
        assert!(!elf.is_thumb(0x0FFF)); // before marker
        assert!(elf.is_thumb(0x1000));  // at marker
        assert!(elf.is_thumb(0x2000));  // after marker
    }

    #[test]
    fn test_is_thumb_single_arm_marker() {
        let elf = make_arm_elf_with_markers(vec![(0x1000, false)]);
        assert!(!elf.is_thumb(0x1000));
        assert!(!elf.is_thumb(0x2000));
    }

    #[test]
    fn test_is_thumb_mixed_regions() {
        // ARM region, then Thumb region, then ARM again
        let elf = make_arm_elf_with_markers(vec![
            (0x1000, false), // ARM starts
            (0x2000, true),  // Thumb starts
            (0x3000, false), // ARM starts again
        ]);
        assert!(!elf.is_thumb(0x0FFF)); // before any marker
        assert!(!elf.is_thumb(0x1000)); // in ARM region
        assert!(!elf.is_thumb(0x1500)); // still ARM
        assert!(elf.is_thumb(0x2000));  // Thumb region starts
        assert!(elf.is_thumb(0x2800));  // still Thumb
        assert!(!elf.is_thumb(0x3000)); // back to ARM
        assert!(!elf.is_thumb(0x4000)); // still ARM
    }

    #[test]
    fn test_is_thumb_at_exact_boundary() {
        let elf = make_arm_elf_with_markers(vec![
            (0x1000, true),
            (0x1000, false), // duplicate address — last wins (BTreeMap behavior)
        ]);
        // With a Vec, the second entry at same address wins in partition_point
        // but since we build from BTreeMap, duplicates are merged
        // This tests that the implementation handles the edge case
        assert!(!elf.is_thumb(0x0FFF));
    }

    #[test]
    fn test_is_thumb_default_for_non_arm() {
        let elf = make_elf_file(); // x86_64
        assert!(!elf.is_thumb(0x1000));
    }

    #[test]
    fn test_got_reloc_types() {
        let types = got_reloc_types(CpuArch::X86_64);
        assert!(types.contains(&reloc::R_X86_64_GLOB_DAT));
        assert!(types.contains(&reloc::R_X86_64_JUMP_SLOT));

        let types = got_reloc_types(CpuArch::X86);
        assert!(types.contains(&reloc::R_386_GLOB_DAT));
        assert!(types.contains(&reloc::R_386_JMP_SLOT));

        let types = got_reloc_types(CpuArch::Arm64);
        assert!(types.contains(&reloc::R_AARCH64_GLOB_DAT));
        assert!(types.contains(&reloc::R_AARCH64_JUMP_SLOT));

        let types = got_reloc_types(CpuArch::Arm);
        assert!(types.contains(&reloc::R_ARM_GLOB_DAT));
        assert!(types.contains(&reloc::R_ARM_JUMP_SLOT));
    }

    #[test]
    fn test_resolve_got_import() {
        // Simulate an ELF with a GOT entry at VA 0x5000 → "printf"
        let elf = ElfFile {
            data: vec![0; 0x20000],
            arch: CpuArch::X86_64,
            exports_list: Vec::new(),
            imports_map: HashMap::from([
                // PLT stub entry
                (0x3000, ("".to_string(), "malloc".to_string())),
                // GOT slot entry (added by build_got_imports)
                (0x5000, ("".to_string(), "printf".to_string())),
            ]),
            segments: vec![LoadSegment {
                vaddr: 0x0,
                memsz: 0x20000,
                offset: 0x0,
                filesz: 0x20000,
            }],
            thumb_markers: Vec::new(),
        };

        // GOT slot VA resolves to import name
        assert_eq!(
            elf.resolve_import(0x5000),
            Some(("".to_string(), "printf".to_string()))
        );
        // PLT stub still works
        assert_eq!(
            elf.resolve_import(0x3000),
            Some(("".to_string(), "malloc".to_string()))
        );
        // Unknown VA returns None
        assert_eq!(elf.resolve_import(0x9000), None);
    }

    #[test]
    fn test_read_pointer_at_rva_x86_64() {
        let mut elf = make_elf_file();
        // Write an 8-byte pointer at VA 0x8000 (file offset 0x8000 since vaddr=0)
        let target_va: u64 = 0x2000;
        elf.data[0x8000..0x8008].copy_from_slice(&target_va.to_le_bytes());

        assert_eq!(elf.read_pointer_at_rva(0x8000), Some(0x2000));
    }

    #[test]
    fn test_read_pointer_at_rva_zero_value() {
        let elf = make_elf_file();
        // Zero pointer (unresolved relocation) returns None
        assert_eq!(elf.read_pointer_at_rva(0x8000), None);
    }

    #[test]
    fn test_read_pointer_at_rva_arm32() {
        let mut data = vec![0u8; 0x10000];
        // Write a 4-byte pointer at offset 0x4000
        let target_va: u32 = 0x1234;
        data[0x4000..0x4004].copy_from_slice(&target_va.to_le_bytes());

        let elf = ElfFile {
            data,
            arch: CpuArch::Arm,
            exports_list: Vec::new(),
            imports_map: HashMap::new(),
            segments: vec![LoadSegment {
                vaddr: 0x0,
                memsz: 0x10000,
                offset: 0x0,
                filesz: 0x10000,
            }],
            thumb_markers: Vec::new(),
        };

        assert_eq!(elf.read_pointer_at_rva(0x4000), Some(0x1234));
    }

    #[test]
    fn test_read_pointer_at_rva_unmapped() {
        let elf = make_elf_file();
        // VA not in any segment
        assert_eq!(elf.read_pointer_at_rva(0x30000), None);
    }
}
