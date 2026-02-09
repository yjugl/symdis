// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::collections::HashMap;
use std::io::BufRead;

use anyhow::{Result, Context, bail};

/// Parsed Breakpad .sym file.
pub struct SymFile {
    pub module: ModuleRecord,
    pub files: Vec<String>,
    pub functions: Vec<FuncRecord>,
    pub publics: Vec<PublicRecord>,
    pub inline_origins: Vec<String>,
    /// Map from function name to index in `functions` for fast lookup.
    name_index: HashMap<String, Vec<usize>>,
}

pub struct ModuleRecord {
    pub os: String,
    pub arch: String,
    pub debug_id: String,
    pub name: String,
}

pub struct FuncRecord {
    pub address: u64,
    pub size: u64,
    pub param_size: u64,
    pub name: String,
    pub lines: Vec<LineRecord>,
    pub inlines: Vec<InlineRecord>,
}

#[derive(Clone)]
pub struct LineRecord {
    pub address: u64,
    pub size: u64,
    pub line: u32,
    pub file_index: usize,
}

pub struct InlineRecord {
    pub depth: u32,
    pub call_line: u32,
    pub call_file_index: usize,
    pub origin_index: usize,
    pub ranges: Vec<(u64, u64)>,
}

pub struct PublicRecord {
    pub address: u64,
    pub param_size: u64,
    pub name: String,
}

/// Symbol lookup result.
pub struct SymbolInfo {
    pub name: String,
    pub address: u64,
    pub size: Option<u64>,
    pub offset_in_function: u64,
}

/// Source location result.
pub struct SourceLocation {
    pub file: String,
    pub line: u32,
}

/// Information about an inline frame active at a given address.
pub struct InlineInfo {
    pub name: String,
    pub depth: u32,
    pub call_file: Option<String>,
    pub call_line: u32,
}

/// Summary statistics from a .sym file, extracted without full parsing.
pub struct SymFileSummary {
    pub module: ModuleRecord,
    pub function_count: usize,
    pub public_count: usize,
}

impl SymFileSummary {
    /// Scan a .sym file to extract the MODULE record and count FUNC/PUBLIC records.
    /// Much cheaper than a full parse — no allocations per record.
    pub fn scan<R: BufRead>(reader: R) -> Result<Self> {
        let mut module: Option<ModuleRecord> = None;
        let mut function_count: usize = 0;
        let mut public_count: usize = 0;

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();

            if let Some(rest) = line.strip_prefix("MODULE ") {
                if module.is_none() {
                    module = Some(parse_module_record(rest)?);
                }
            } else if line.starts_with("FUNC ") {
                function_count += 1;
            } else if line.starts_with("PUBLIC ") {
                public_count += 1;
            }
        }

        let module = module.ok_or_else(|| anyhow::anyhow!("no MODULE record found"))?;
        Ok(Self { module, function_count, public_count })
    }
}

impl SymFile {
    /// Parse a .sym file from a reader.
    pub fn parse<R: BufRead>(reader: R) -> Result<Self> {
        let mut module: Option<ModuleRecord> = None;
        let mut files: Vec<String> = Vec::new();
        let mut functions: Vec<FuncRecord> = Vec::new();
        let mut publics: Vec<PublicRecord> = Vec::new();
        let mut inline_origins: Vec<String> = Vec::new();
        let mut current_func: Option<FuncRecord> = None;

        for (line_num, line) in reader.lines().enumerate() {
            let line = line.with_context(|| format!("reading line {}", line_num + 1))?;
            let line = line.trim();

            if line.is_empty() {
                continue;
            }

            if let Some(rest) = line.strip_prefix("MODULE ") {
                module = Some(parse_module_record(rest)?);
            } else if let Some(rest) = line.strip_prefix("FILE ") {
                parse_file_record(rest, &mut files)?;
            } else if let Some(rest) = line.strip_prefix("FUNC ") {
                // Save previous function
                if let Some(func) = current_func.take() {
                    functions.push(func);
                }
                current_func = Some(parse_func_record(rest)?);
            } else if let Some(rest) = line.strip_prefix("PUBLIC ") {
                publics.push(parse_public_record(rest)?);
            } else if let Some(rest) = line.strip_prefix("INLINE_ORIGIN ") {
                parse_inline_origin(rest, &mut inline_origins)?;
            } else if let Some(rest) = line.strip_prefix("INLINE ") {
                if let Some(ref mut func) = current_func {
                    func.inlines.push(parse_inline_record(rest)?);
                }
            } else if line.starts_with("STACK ") {
                // Skip STACK records
            } else if line.starts_with("INFO ") {
                // Skip INFO records
            } else if current_func.is_some() {
                // This should be a line record (no prefix, part of current FUNC)
                if let Some(ref mut func) = current_func {
                    if let Ok(lr) = parse_line_record(line) {
                        func.lines.push(lr);
                    }
                    // Silently skip unparseable lines within a function
                }
            }
        }

        // Don't forget the last function
        if let Some(func) = current_func {
            functions.push(func);
        }

        let module = module.ok_or_else(|| anyhow::anyhow!("no MODULE record found"))?;

        // Sort functions and publics by address
        functions.sort_by_key(|f| f.address);
        publics.sort_by_key(|p| p.address);

        // Build name index
        let mut name_index: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, func) in functions.iter().enumerate() {
            name_index
                .entry(func.name.clone())
                .or_default()
                .push(i);
        }

        Ok(Self {
            module,
            files,
            functions,
            publics,
            inline_origins,
            name_index,
        })
    }

    /// Find a function by exact name.
    pub fn find_function_by_name(&self, name: &str) -> Option<&FuncRecord> {
        self.name_index
            .get(name)
            .and_then(|indices| indices.first())
            .map(|&i| &self.functions[i])
    }

    /// Find functions by substring match.
    pub fn find_function_by_name_fuzzy(&self, pattern: &str) -> Vec<&FuncRecord> {
        self.functions
            .iter()
            .filter(|f| f.name.contains(pattern))
            .collect()
    }

    /// Find the function containing a given address.
    pub fn find_function_at_address(&self, addr: u64) -> Option<&FuncRecord> {
        // Binary search for the function whose range contains addr
        let idx = self.functions.partition_point(|f| f.address <= addr);
        if idx == 0 {
            return None;
        }
        let func = &self.functions[idx - 1];
        if addr < func.address + func.size {
            Some(func)
        } else {
            None
        }
    }

    /// Find the PUBLIC symbol at or just before a given address.
    pub fn find_public_at_address(&self, addr: u64) -> Option<&PublicRecord> {
        let idx = self.publics.partition_point(|p| p.address <= addr);
        if idx == 0 {
            return None;
        }
        Some(&self.publics[idx - 1])
    }

    /// Resolve an address to a symbol name + offset.
    /// Tries FUNC records first, falls back to PUBLIC records.
    pub fn resolve_address(&self, addr: u64) -> Option<SymbolInfo> {
        if let Some(func) = self.find_function_at_address(addr) {
            return Some(SymbolInfo {
                name: func.name.clone(),
                address: func.address,
                size: Some(func.size),
                offset_in_function: addr - func.address,
            });
        }

        if let Some(public) = self.find_public_at_address(addr) {
            // PUBLIC symbols have no size, so cap the max distance to avoid
            // bogus matches for addresses far from any known symbol.
            const MAX_PUBLIC_DISTANCE: u64 = 0x10000; // 64KB
            if addr - public.address < MAX_PUBLIC_DISTANCE {
                return Some(SymbolInfo {
                    name: public.name.clone(),
                    address: public.address,
                    size: None,
                    offset_in_function: addr - public.address,
                });
            }
        }

        None
    }

    /// Get all inline frames active at a given address within a function.
    /// Returns frames sorted by depth (outermost first).
    pub fn get_inline_at(&self, addr: u64, func: &FuncRecord) -> Vec<InlineInfo> {
        let mut result = Vec::new();
        for inline in &func.inlines {
            let active = inline.ranges.iter().any(|&(range_addr, range_size)| {
                addr >= range_addr && addr < range_addr + range_size
            });
            if active {
                let name = self
                    .inline_origins
                    .get(inline.origin_index)
                    .cloned()
                    .unwrap_or_else(|| format!("<inline {}>", inline.origin_index));
                let call_file = self.files.get(inline.call_file_index).cloned();
                result.push(InlineInfo {
                    name,
                    depth: inline.depth,
                    call_file,
                    call_line: inline.call_line,
                });
            }
        }
        result.sort_by_key(|i| i.depth);
        result
    }

    /// Get the source file and line for an address within a function.
    pub fn get_source_line(&self, addr: u64, func: &FuncRecord) -> Option<SourceLocation> {
        // Find the line record covering this address
        // Line records are sorted by address within a function
        let idx = func.lines.partition_point(|l| l.address <= addr);
        if idx == 0 {
            return None;
        }
        let line = &func.lines[idx - 1];
        if addr < line.address + line.size {
            let file = self
                .files
                .get(line.file_index)
                .cloned()
                .unwrap_or_else(|| format!("<file {}>", line.file_index));
            Some(SourceLocation {
                file,
                line: line.line,
            })
        } else {
            None
        }
    }
}

fn parse_module_record(rest: &str) -> Result<ModuleRecord> {
    // MODULE <os> <arch> <debug_id> <name>
    let parts: Vec<&str> = rest.splitn(4, ' ').collect();
    if parts.len() < 4 {
        bail!("invalid MODULE record: not enough fields");
    }
    Ok(ModuleRecord {
        os: parts[0].to_string(),
        arch: parts[1].to_string(),
        debug_id: parts[2].to_string(),
        name: parts[3].to_string(),
    })
}

fn parse_file_record(rest: &str, files: &mut Vec<String>) -> Result<()> {
    // FILE <index> <source_path>
    let (idx_str, path) = rest
        .split_once(' ')
        .ok_or_else(|| anyhow::anyhow!("invalid FILE record"))?;
    let idx: usize = idx_str.parse().context("invalid FILE index")?;
    // Ensure the vector is large enough
    if idx >= files.len() {
        files.resize(idx + 1, String::new());
    }
    files[idx] = path.to_string();
    Ok(())
}

fn parse_func_record(rest: &str) -> Result<FuncRecord> {
    // FUNC [m] <addr> <size> <param_size> <name>
    let rest = rest.strip_prefix("m ").unwrap_or(rest);
    let parts: Vec<&str> = rest.splitn(4, ' ').collect();
    if parts.len() < 4 {
        bail!("invalid FUNC record: not enough fields");
    }
    Ok(FuncRecord {
        address: u64::from_str_radix(parts[0], 16).context("invalid FUNC address")?,
        size: u64::from_str_radix(parts[1], 16).context("invalid FUNC size")?,
        param_size: u64::from_str_radix(parts[2], 16).context("invalid FUNC param_size")?,
        name: parts[3].to_string(),
        lines: Vec::new(),
        inlines: Vec::new(),
    })
}

fn parse_line_record(line: &str) -> Result<LineRecord> {
    // <addr> <size> <line> <file_index>
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        bail!("invalid line record");
    }
    Ok(LineRecord {
        address: u64::from_str_radix(parts[0], 16).context("invalid line address")?,
        size: u64::from_str_radix(parts[1], 16).context("invalid line size")?,
        line: parts[2].parse().context("invalid line number")?,
        file_index: parts[3].parse().context("invalid file index")?,
    })
}

fn parse_public_record(rest: &str) -> Result<PublicRecord> {
    // PUBLIC [m] <addr> <param_size> <name>
    let rest = rest.strip_prefix("m ").unwrap_or(rest);
    let parts: Vec<&str> = rest.splitn(3, ' ').collect();
    if parts.len() < 3 {
        bail!("invalid PUBLIC record: not enough fields");
    }
    Ok(PublicRecord {
        address: u64::from_str_radix(parts[0], 16).context("invalid PUBLIC address")?,
        param_size: u64::from_str_radix(parts[1], 16).context("invalid PUBLIC param_size")?,
        name: parts[2].to_string(),
    })
}

fn parse_inline_origin(rest: &str, inline_origins: &mut Vec<String>) -> Result<()> {
    // INLINE_ORIGIN <index> <name>
    let (idx_str, name) = rest
        .split_once(' ')
        .ok_or_else(|| anyhow::anyhow!("invalid INLINE_ORIGIN record"))?;
    let idx: usize = idx_str.parse().context("invalid INLINE_ORIGIN index")?;
    if idx >= inline_origins.len() {
        inline_origins.resize(idx + 1, String::new());
    }
    inline_origins[idx] = name.to_string();
    Ok(())
}

fn parse_inline_record(rest: &str) -> Result<InlineRecord> {
    // INLINE <depth> <call_line> <call_file> <origin_index> [<addr> <size>]+
    let parts: Vec<&str> = rest.split_whitespace().collect();
    if parts.len() < 6 || !parts.len().is_multiple_of(2) {
        bail!("invalid INLINE record");
    }
    let depth: u32 = parts[0].parse().context("invalid INLINE depth")?;
    let call_line: u32 = parts[1].parse().context("invalid INLINE call_line")?;
    let call_file_index: usize = parts[2].parse().context("invalid INLINE call_file")?;
    let origin_index: usize = parts[3].parse().context("invalid INLINE origin_index")?;

    let mut ranges = Vec::new();
    let mut i = 4;
    while i + 1 < parts.len() {
        let addr = u64::from_str_radix(parts[i], 16).context("invalid INLINE range address")?;
        let size = u64::from_str_radix(parts[i + 1], 16).context("invalid INLINE range size")?;
        ranges.push((addr, size));
        i += 2;
    }

    Ok(InlineRecord {
        depth,
        call_line,
        call_file_index,
        origin_index,
        ranges,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn make_test_sym() -> &'static str {
        "\
MODULE windows x86_64 44E4EC8C2F41492B9369D6B9A059577C2 test.pdb
FILE 0 src/main.cpp
FILE 1 src/util.cpp
INLINE_ORIGIN 0 InlinedHelper
FUNC 1000 80 0 TestFunction
1000 10 10 0
1010 20 11 0
1030 30 12 0
1060 20 13 0
INLINE 0 10 0 0 1020 10
FUNC 2000 40 0 AnotherFunction
2000 20 5 1
2020 20 6 1
PUBLIC 3000 0 _PublicSymbol
PUBLIC 4000 0 _AnotherPublic
"
    }

    #[test]
    fn test_parse_module() {
        let sym = SymFile::parse(Cursor::new(make_test_sym())).unwrap();
        assert_eq!(sym.module.os, "windows");
        assert_eq!(sym.module.arch, "x86_64");
        assert_eq!(sym.module.debug_id, "44E4EC8C2F41492B9369D6B9A059577C2");
        assert_eq!(sym.module.name, "test.pdb");
    }

    #[test]
    fn test_parse_files() {
        let sym = SymFile::parse(Cursor::new(make_test_sym())).unwrap();
        assert_eq!(sym.files.len(), 2);
        assert_eq!(sym.files[0], "src/main.cpp");
        assert_eq!(sym.files[1], "src/util.cpp");
    }

    #[test]
    fn test_parse_functions() {
        let sym = SymFile::parse(Cursor::new(make_test_sym())).unwrap();
        assert_eq!(sym.functions.len(), 2);
        assert_eq!(sym.functions[0].name, "TestFunction");
        assert_eq!(sym.functions[0].address, 0x1000);
        assert_eq!(sym.functions[0].size, 0x80);
        assert_eq!(sym.functions[0].lines.len(), 4);
    }

    #[test]
    fn test_find_function_by_name() {
        let sym = SymFile::parse(Cursor::new(make_test_sym())).unwrap();
        let func = sym.find_function_by_name("TestFunction").unwrap();
        assert_eq!(func.address, 0x1000);
    }

    #[test]
    fn test_find_function_by_name_not_found() {
        let sym = SymFile::parse(Cursor::new(make_test_sym())).unwrap();
        assert!(sym.find_function_by_name("NonExistent").is_none());
    }

    #[test]
    fn test_find_function_at_address() {
        let sym = SymFile::parse(Cursor::new(make_test_sym())).unwrap();

        // Start of function
        let func = sym.find_function_at_address(0x1000).unwrap();
        assert_eq!(func.name, "TestFunction");

        // Middle of function
        let func = sym.find_function_at_address(0x1040).unwrap();
        assert_eq!(func.name, "TestFunction");

        // Last byte of function
        let func = sym.find_function_at_address(0x107F).unwrap();
        assert_eq!(func.name, "TestFunction");

        // Just past end of function
        assert!(sym.find_function_at_address(0x1080).is_none());

        // Between functions
        assert!(sym.find_function_at_address(0x1500).is_none());

        // Before first function
        assert!(sym.find_function_at_address(0x500).is_none());
    }

    #[test]
    fn test_find_public_at_address() {
        let sym = SymFile::parse(Cursor::new(make_test_sym())).unwrap();

        let public = sym.find_public_at_address(0x3000).unwrap();
        assert_eq!(public.name, "_PublicSymbol");

        let public = sym.find_public_at_address(0x3500).unwrap();
        assert_eq!(public.name, "_PublicSymbol");

        let public = sym.find_public_at_address(0x4000).unwrap();
        assert_eq!(public.name, "_AnotherPublic");
    }

    #[test]
    fn test_resolve_address_func() {
        let sym = SymFile::parse(Cursor::new(make_test_sym())).unwrap();
        let info = sym.resolve_address(0x1020).unwrap();
        assert_eq!(info.name, "TestFunction");
        assert_eq!(info.offset_in_function, 0x20);
        assert_eq!(info.size, Some(0x80));
    }

    #[test]
    fn test_resolve_address_public() {
        let sym = SymFile::parse(Cursor::new(make_test_sym())).unwrap();
        let info = sym.resolve_address(0x3010).unwrap();
        assert_eq!(info.name, "_PublicSymbol");
        assert_eq!(info.offset_in_function, 0x10);
        assert!(info.size.is_none());
    }

    #[test]
    fn test_resolve_address_public_too_far() {
        // Address far beyond any PUBLIC symbol should not resolve
        let sym = SymFile::parse(Cursor::new(make_test_sym())).unwrap();
        assert!(sym.resolve_address(0xdeadbeef).is_none());
    }

    #[test]
    fn test_get_source_line() {
        let sym = SymFile::parse(Cursor::new(make_test_sym())).unwrap();
        let func = sym.find_function_by_name("TestFunction").unwrap();

        let loc = sym.get_source_line(0x1000, func).unwrap();
        assert_eq!(loc.file, "src/main.cpp");
        assert_eq!(loc.line, 10);

        let loc = sym.get_source_line(0x1015, func).unwrap();
        assert_eq!(loc.line, 11);

        let loc = sym.get_source_line(0x1050, func).unwrap();
        assert_eq!(loc.line, 12);
    }

    #[test]
    fn test_fuzzy_search() {
        let sym = SymFile::parse(Cursor::new(make_test_sym())).unwrap();
        let results = sym.find_function_by_name_fuzzy("Function");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_parse_publics() {
        let sym = SymFile::parse(Cursor::new(make_test_sym())).unwrap();
        assert_eq!(sym.publics.len(), 2);
        assert_eq!(sym.publics[0].address, 0x3000);
        assert_eq!(sym.publics[0].name, "_PublicSymbol");
    }

    #[test]
    fn test_inline_origins() {
        let sym = SymFile::parse(Cursor::new(make_test_sym())).unwrap();
        assert_eq!(sym.inline_origins.len(), 1);
        assert_eq!(sym.inline_origins[0], "InlinedHelper");
    }

    #[test]
    fn test_inline_records() {
        let sym = SymFile::parse(Cursor::new(make_test_sym())).unwrap();
        let func = sym.find_function_by_name("TestFunction").unwrap();
        assert_eq!(func.inlines.len(), 1);
        assert_eq!(func.inlines[0].ranges.len(), 1);
        assert_eq!(func.inlines[0].ranges[0], (0x1020, 0x10));
    }

    #[test]
    fn test_summary_scan() {
        let summary = SymFileSummary::scan(Cursor::new(make_test_sym())).unwrap();
        assert_eq!(summary.module.os, "windows");
        assert_eq!(summary.module.arch, "x86_64");
        assert_eq!(summary.module.debug_id, "44E4EC8C2F41492B9369D6B9A059577C2");
        assert_eq!(summary.function_count, 2);
        assert_eq!(summary.public_count, 2);
    }
}
