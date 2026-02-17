// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Result, Context, bail};
use goblin::mach::constants::cputype::*;
use goblin::mach::constants::{SECTION_TYPE, S_SYMBOL_STUBS};
use goblin::mach::exports::ExportInfo;
use goblin::mach::load_command::{
    CommandVariant, SIZEOF_SECTION_32, SIZEOF_SECTION_64, SIZEOF_SEGMENT_COMMAND_32,
    SIZEOF_SEGMENT_COMMAND_64,
};
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

        // Collect imports (lazy/non-lazy pointer addresses)
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

        // Build stub imports from indirect symbol table (__stubs section)
        // so that direct calls to stubs resolve to import names
        let stub_imports = build_stub_imports(data, macho, &imports_map);
        imports_map.extend(stub_imports);

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

/// Build a mapping from `__stubs` entry addresses to import names.
///
/// On macOS, external function calls go through `__stubs` entries (e.g.,
/// `call <__stubs+0x42>` on x86-64, `bl <__stubs+0x30>` on AArch64).
/// This function maps each stub address to its target symbol name by
/// reading the Mach-O indirect symbol table.
fn build_stub_imports(
    data: &[u8],
    macho: &MachO,
    existing_imports: &HashMap<u64, (String, String)>,
) -> HashMap<u64, (String, String)> {
    let mut map = HashMap::new();

    // Find LC_DYSYMTAB for indirect symbol table location
    let mut indirectsymoff: u32 = 0;
    let mut nindirectsyms: u32 = 0;
    for cmd in &macho.load_commands {
        if let CommandVariant::Dysymtab(dysymtab) = &cmd.command {
            indirectsymoff = dysymtab.indirectsymoff;
            nindirectsyms = dysymtab.nindirectsyms;
            break;
        }
    }
    if nindirectsyms == 0 {
        return map;
    }

    // Build reverse lookup: symbol name → dylib from existing imports
    let name_to_dylib: HashMap<&str, &str> = existing_imports
        .values()
        .map(|(dylib, name)| (name.as_str(), dylib.as_str()))
        .collect();

    // Get symbol table for name lookup (need Symbols::get for index-based access)
    let symbols = match &macho.symbols {
        Some(s) => s,
        None => return map,
    };

    // Collect stub sections: (addr, size, reserved1, reserved2)
    // reserved1 = starting index into indirect symbol table
    // reserved2 = stub entry size in bytes
    let mut stub_sections: Vec<(u64, u64, u32, u32)> = Vec::new();

    for cmd in &macho.load_commands {
        match &cmd.command {
            CommandVariant::Segment64(seg) => {
                let sections_start = cmd.offset + SIZEOF_SEGMENT_COMMAND_64;
                for i in 0..seg.nsects as usize {
                    let off = sections_start + i * SIZEOF_SECTION_64;
                    if off + SIZEOF_SECTION_64 > data.len() {
                        break;
                    }
                    let flags = u32::from_le_bytes(
                        data[off + 64..off + 68].try_into().unwrap(),
                    );
                    if flags & SECTION_TYPE != S_SYMBOL_STUBS {
                        continue;
                    }
                    let addr =
                        u64::from_le_bytes(data[off + 32..off + 40].try_into().unwrap());
                    let size =
                        u64::from_le_bytes(data[off + 40..off + 48].try_into().unwrap());
                    let reserved1 =
                        u32::from_le_bytes(data[off + 68..off + 72].try_into().unwrap());
                    let reserved2 =
                        u32::from_le_bytes(data[off + 72..off + 76].try_into().unwrap());
                    stub_sections.push((addr, size, reserved1, reserved2));
                }
            }
            CommandVariant::Segment32(seg) => {
                let sections_start = cmd.offset + SIZEOF_SEGMENT_COMMAND_32;
                for i in 0..seg.nsects as usize {
                    let off = sections_start + i * SIZEOF_SECTION_32;
                    if off + SIZEOF_SECTION_32 > data.len() {
                        break;
                    }
                    let flags = u32::from_le_bytes(
                        data[off + 56..off + 60].try_into().unwrap(),
                    );
                    if flags & SECTION_TYPE != S_SYMBOL_STUBS {
                        continue;
                    }
                    let addr = u32::from_le_bytes(
                        data[off + 32..off + 36].try_into().unwrap(),
                    ) as u64;
                    let size = u32::from_le_bytes(
                        data[off + 36..off + 40].try_into().unwrap(),
                    ) as u64;
                    let reserved1 =
                        u32::from_le_bytes(data[off + 60..off + 64].try_into().unwrap());
                    let reserved2 =
                        u32::from_le_bytes(data[off + 64..off + 68].try_into().unwrap());
                    stub_sections.push((addr, size, reserved1, reserved2));
                }
            }
            _ => {}
        }
    }

    // Process each stub section
    for (addr, size, reserved1, reserved2) in stub_sections {
        if reserved2 == 0 {
            continue;
        }
        let stub_size = reserved2 as u64;
        let n_stubs = size / stub_size;

        for j in 0..n_stubs {
            let stub_addr = addr + j * stub_size;
            let isym_idx = reserved1 as usize + j as usize;
            if isym_idx >= nindirectsyms as usize {
                break;
            }

            let isym_off = indirectsymoff as usize + isym_idx * 4;
            if isym_off + 4 > data.len() {
                break;
            }

            let sym_idx =
                u32::from_le_bytes(data[isym_off..isym_off + 4].try_into().unwrap());

            // Skip INDIRECT_SYMBOL_LOCAL and INDIRECT_SYMBOL_ABS
            if sym_idx & (0x80000000 | 0x40000000) != 0 {
                continue;
            }

            if let Ok((name, _nlist)) = symbols.get(sym_idx as usize) {
                if !name.is_empty() {
                    let dylib = name_to_dylib
                        .get(name)
                        .copied()
                        .unwrap_or("")
                        .to_string();
                    map.insert(stub_addr, (dylib, name.to_string()));
                }
            }
        }
    }

    map
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

    fn write_u32_le(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64_le(data: &mut [u8], offset: usize, value: u64) {
        data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    /// Build a minimal synthetic 64-bit x86_64 Mach-O with a __stubs section.
    ///
    /// Layout:
    ///   0x000..0x020  mach_header_64
    ///   0x020..0x0B8  LC_SEGMENT_64 (72) + Section64 __stubs (80)
    ///   0x0B8..0x0D0  LC_SYMTAB (24)
    ///   0x0D0..0x120  LC_DYSYMTAB (80)
    ///   0x120..0x150  Symbol table (3 × nlist_64 = 48)
    ///   0x150..0x168  String table (24 bytes)
    ///   0x168..0x178  Indirect symbol table (4 × u32 = 16)
    ///   0x180..0x198  Stub code (4 × 6 bytes = 24)
    fn make_synthetic_macho_with_stubs() -> Vec<u8> {
        let mut data = vec![0u8; 0x200];

        // --- mach_header_64 (32 bytes) ---
        write_u32_le(&mut data, 0, 0xFEEDFACF); // magic = MH_MAGIC_64
        write_u32_le(&mut data, 4, 0x01000007); // cputype = CPU_TYPE_X86_64
        write_u32_le(&mut data, 8, 0x00000003); // cpusubtype
        write_u32_le(&mut data, 12, 2); // filetype = MH_EXECUTE
        write_u32_le(&mut data, 16, 3); // ncmds
        write_u32_le(&mut data, 20, 256); // sizeofcmds = 152 + 24 + 80

        // --- LC_SEGMENT_64 at 0x20 (152 bytes: 72 header + 80 section) ---
        let seg = 0x20;
        write_u32_le(&mut data, seg, 0x19); // cmd = LC_SEGMENT_64
        write_u32_le(&mut data, seg + 4, 152); // cmdsize
        data[seg + 8..seg + 14].copy_from_slice(b"__TEXT");
        write_u64_le(&mut data, seg + 24, 0); // vmaddr
        write_u64_le(&mut data, seg + 32, 0x200); // vmsize
        write_u64_le(&mut data, seg + 40, 0); // fileoff
        write_u64_le(&mut data, seg + 48, 0x200); // filesize
        write_u32_le(&mut data, seg + 56, 7); // maxprot
        write_u32_le(&mut data, seg + 60, 5); // initprot
        write_u32_le(&mut data, seg + 64, 1); // nsects

        // --- Section64 (__stubs) at 0x68 ---
        let sect = seg + 72;
        data[sect..sect + 7].copy_from_slice(b"__stubs");
        data[sect + 16..sect + 22].copy_from_slice(b"__TEXT");
        write_u64_le(&mut data, sect + 32, 0x180); // addr
        write_u64_le(&mut data, sect + 40, 24); // size = 4 stubs × 6 bytes
        write_u32_le(&mut data, sect + 48, 0x180); // offset
        write_u32_le(&mut data, sect + 64, 0x08); // flags = S_SYMBOL_STUBS
        write_u32_le(&mut data, sect + 68, 0); // reserved1 = indirect sym start index
        write_u32_le(&mut data, sect + 72, 6); // reserved2 = stub entry size

        // --- LC_SYMTAB at 0xB8 (24 bytes) ---
        let sym_cmd = 0xB8;
        write_u32_le(&mut data, sym_cmd, 0x02); // cmd = LC_SYMTAB
        write_u32_le(&mut data, sym_cmd + 4, 24);
        write_u32_le(&mut data, sym_cmd + 8, 0x120); // symoff
        write_u32_le(&mut data, sym_cmd + 12, 3); // nsyms
        write_u32_le(&mut data, sym_cmd + 16, 0x150); // stroff
        write_u32_le(&mut data, sym_cmd + 20, 24); // strsize

        // --- LC_DYSYMTAB at 0xD0 (80 bytes) ---
        let dysym = 0xD0;
        write_u32_le(&mut data, dysym, 0x0B); // cmd = LC_DYSYMTAB
        write_u32_le(&mut data, dysym + 4, 80);
        write_u32_le(&mut data, dysym + 28, 3); // nundefsym
        write_u32_le(&mut data, dysym + 56, 0x168); // indirectsymoff
        write_u32_le(&mut data, dysym + 60, 4); // nindirectsyms

        // --- Symbol table at 0x120 (3 × nlist_64 = 48 bytes) ---
        // nlist_64: n_strx(u32) + n_type(u8) + n_sect(u8) + n_desc(u16) + n_value(u64)
        let sym = 0x120;
        write_u32_le(&mut data, sym, 1); // sym[0].n_strx → "_malloc"
        data[sym + 4] = 0x01; // n_type = N_EXT
        write_u32_le(&mut data, sym + 16, 9); // sym[1].n_strx → "_printf"
        data[sym + 20] = 0x01;
        write_u32_le(&mut data, sym + 32, 17); // sym[2].n_strx → "_exit"
        data[sym + 36] = 0x01;

        // --- String table at 0x150 (24 bytes) ---
        // "\0_malloc\0_printf\0_exit\0..."
        let st = 0x150;
        data[st] = 0; // empty string at index 0
        data[st + 1..st + 8].copy_from_slice(b"_malloc");
        data[st + 8] = 0;
        data[st + 9..st + 16].copy_from_slice(b"_printf");
        data[st + 16] = 0;
        data[st + 17..st + 22].copy_from_slice(b"_exit");
        data[st + 22] = 0;

        // --- Indirect symbol table at 0x168 (4 × u32 = 16 bytes) ---
        let isym = 0x168;
        write_u32_le(&mut data, isym, 0); // stub 0 → symbol 0 (_malloc)
        write_u32_le(&mut data, isym + 4, 1); // stub 1 → symbol 1 (_printf)
        write_u32_le(&mut data, isym + 8, 2); // stub 2 → symbol 2 (_exit)
        write_u32_le(&mut data, isym + 12, 0x80000000); // stub 3 → INDIRECT_SYMBOL_LOCAL

        // --- Stub code at 0x180 (24 bytes of int3 placeholders) ---
        for i in 0..24 {
            data[0x180 + i] = 0xCC;
        }

        data
    }

    #[test]
    fn test_stub_imports() {
        let data = make_synthetic_macho_with_stubs();
        let macho_file = MachOFile::from_bytes(data, None).unwrap();

        // Valid stubs resolve to symbol names
        assert_eq!(
            macho_file.resolve_import(0x180),
            Some(("".to_string(), "_malloc".to_string()))
        );
        assert_eq!(
            macho_file.resolve_import(0x186),
            Some(("".to_string(), "_printf".to_string()))
        );
        assert_eq!(
            macho_file.resolve_import(0x18C),
            Some(("".to_string(), "_exit".to_string()))
        );

        // Stub 3 uses INDIRECT_SYMBOL_LOCAL — should be skipped
        assert_eq!(macho_file.resolve_import(0x192), None);

        // Non-stub address should not resolve
        assert_eq!(macho_file.resolve_import(0x100), None);
    }

    #[test]
    fn test_stub_imports_arch() {
        let data = make_synthetic_macho_with_stubs();
        let macho_file = MachOFile::from_bytes(data, None).unwrap();
        assert_eq!(macho_file.arch(), CpuArch::X86_64);
    }
}
