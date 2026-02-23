// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{bail, Context, Result};
use pdb::FallibleIterator;

use super::breakpad::{FuncRecord, InlineRecord, LineRecord, ModuleRecord, PublicRecord, SymFile};

/// Extract code ranges from an InlineSiteSymbol's binary annotations.
///
/// The annotations encode a state machine with deltas from the parent
/// procedure's section:offset. Each "emitting" opcode produces a code range
/// where the inlined function is active.
fn extract_inline_ranges(
    annotations: &pdb::BinaryAnnotations<'_>,
    proc_offset: pdb::PdbInternalSectionOffset,
    address_map: &pdb::AddressMap<'_>,
) -> Vec<(u64, u64)> {
    struct Emission {
        offset: pdb::PdbInternalSectionOffset,
        length: Option<u32>,
    }

    let mut emissions: Vec<Emission> = Vec::new();
    let mut code_offset = proc_offset;
    let mut code_offset_base: u32 = 0;
    let mut code_length: Option<u32> = None;

    let mut ann_iter = annotations.iter();
    while let Ok(Some(annotation)) = ann_iter.next() {
        match annotation {
            pdb::BinaryAnnotation::CodeOffset(offset) => {
                code_offset.offset = offset;
            }
            pdb::BinaryAnnotation::ChangeCodeOffsetBase(base) => {
                code_offset_base = base;
            }
            pdb::BinaryAnnotation::ChangeCodeOffset(delta) => {
                code_offset.offset = code_offset.offset.wrapping_add(delta);
                emissions.push(Emission {
                    offset: pdb::PdbInternalSectionOffset {
                        offset: code_offset.offset.wrapping_add(code_offset_base),
                        section: code_offset.section,
                    },
                    length: code_length.take(),
                });
            }
            pdb::BinaryAnnotation::ChangeCodeOffsetAndLineOffset(code_delta, _) => {
                code_offset.offset = code_offset.offset.wrapping_add(code_delta);
                emissions.push(Emission {
                    offset: pdb::PdbInternalSectionOffset {
                        offset: code_offset.offset.wrapping_add(code_offset_base),
                        section: code_offset.section,
                    },
                    length: code_length.take(),
                });
            }
            pdb::BinaryAnnotation::ChangeCodeLengthAndCodeOffset(length, code_delta) => {
                code_length = Some(length);
                code_offset.offset = code_offset.offset.wrapping_add(code_delta);
                emissions.push(Emission {
                    offset: pdb::PdbInternalSectionOffset {
                        offset: code_offset.offset.wrapping_add(code_offset_base),
                        section: code_offset.section,
                    },
                    length: code_length.take(),
                });
            }
            pdb::BinaryAnnotation::ChangeCodeLength(length) => {
                // Update previous record's length if not explicitly set
                if let Some(last) = emissions.last_mut() {
                    if last.length.is_none() {
                        last.length = Some(length);
                    }
                }
                code_offset.offset = code_offset.offset.wrapping_add(length);
            }
            _ => {}
        }
    }

    // Convert emissions to (RVA, length) ranges
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    for i in 0..emissions.len() {
        let length = match emissions[i].length {
            Some(l) => l,
            None => {
                // Infer length from distance to next emission
                if i + 1 < emissions.len() {
                    emissions[i + 1]
                        .offset
                        .offset
                        .saturating_sub(emissions[i].offset.offset)
                } else {
                    continue; // Skip last record with unknown length
                }
            }
        };
        if length > 0 {
            if let Some(rva) = emissions[i].offset.to_rva(address_map) {
                ranges.push((u64::from(rva.0), u64::from(length)));
            }
        }
    }

    ranges
}

/// Parse a srcsrv stream from a PDB file and build a mapping from raw build
/// paths to VCS-style paths (e.g., `hg:hg.mozilla.org/...:path:changeset`).
///
/// The srcsrv stream is a text-based format embedded in Microsoft PDB files that
/// maps source file build paths to version control retrieval commands. Mozilla
/// PDB files contain srcsrv data mapping to Mercurial and GitHub repos.
fn parse_srcsrv_stream(data: &[u8]) -> HashMap<String, String> {
    let text = match std::str::from_utf8(data) {
        Ok(t) => t,
        Err(_) => return HashMap::new(),
    };

    let mut variables: HashMap<String, String> = HashMap::new();
    let mut source_lines: Vec<&str> = Vec::new();

    enum Section {
        None,
        Variables,
        SourceFiles,
    }
    let mut section = Section::None;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("SRCSRV: ini") {
            section = Section::None;
        } else if trimmed.starts_with("SRCSRV: variables") {
            section = Section::Variables;
        } else if trimmed.starts_with("SRCSRV: source files") {
            section = Section::SourceFiles;
        } else if trimmed.starts_with("SRCSRV: end") {
            break;
        } else {
            match section {
                Section::Variables => {
                    if let Some((key, value)) = trimmed.split_once('=') {
                        variables.insert(key.to_uppercase(), value.to_string());
                    }
                }
                Section::SourceFiles => {
                    if !trimmed.is_empty() {
                        source_lines.push(trimmed);
                    }
                }
                Section::None => {}
            }
        }
    }

    // Resolve target variable URL templates to determine VCS type + host.
    let mut target_prefixes: HashMap<String, String> = HashMap::new();
    for (key, value) in &variables {
        if !key.ends_with("_TARGET") {
            continue;
        }
        let resolved = resolve_srcsrv_vars(value, &variables);
        if let Some(prefix) = extract_vcs_prefix(&resolved) {
            target_prefixes.insert(key.clone(), prefix);
        }
    }

    // Build build_path → VCS path map from source file entries.
    let mut path_map = HashMap::new();
    for line in source_lines {
        let parts: Vec<&str> = line.split('*').collect();
        if parts.len() >= 4 {
            let build_path = parts[0].replace('\\', "/");
            let target_var = parts[1].to_uppercase();
            let repo_path = parts[2];
            let changeset = parts[3];
            if let Some(prefix) = target_prefixes.get(&target_var) {
                path_map.insert(build_path, format!("{prefix}:{repo_path}:{changeset}"));
            }
        }
    }

    path_map
}

/// Resolve `%variable%` references in a srcsrv template string.
fn resolve_srcsrv_vars(template: &str, variables: &HashMap<String, String>) -> String {
    let mut result = String::with_capacity(template.len());
    let mut chars = template.chars();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            let mut var_name = String::new();
            let mut found_end = false;
            for ch in chars.by_ref() {
                if ch == '%' {
                    found_end = true;
                    break;
                }
                var_name.push(ch);
            }
            if found_end {
                if let Some(value) = variables.get(&var_name.to_uppercase()) {
                    result.push_str(value);
                } else {
                    result.push('%');
                    result.push_str(&var_name);
                    result.push('%');
                }
            } else {
                result.push('%');
                result.push_str(&var_name);
            }
        } else {
            result.push(ch);
        }
    }

    result
}

/// Extract a VCS prefix from a resolved srcsrv URL template.
///
/// Returns e.g. `"hg:hg.mozilla.org/releases/mozilla-esr140"` for Mercurial
/// or `"git:github.com/rust-lang/rust"` for GitHub.
fn extract_vcs_prefix(url: &str) -> Option<String> {
    let host_and_path = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);

    // Mercurial: URL contains /raw-file/ (hg web interface pattern)
    if host_and_path.contains("/raw-file/") {
        let before = host_and_path.split("/raw-file/").next().unwrap();
        return Some(format!("hg:{before}"));
    }

    // Git/GitHub: URL starts with github.com/org/repo/...
    if host_and_path.starts_with("github.com/") {
        let path_parts: Vec<&str> = host_and_path.splitn(4, '/').collect();
        if path_parts.len() >= 3 {
            return Some(format!(
                "git:{}/{}",
                path_parts[0],
                path_parts[1..3].join("/")
            ));
        }
    }

    None
}

/// Parse a PDB file and convert it into a SymFile.
///
/// This bridges the `pdb` crate's data model into symdis's SymFile struct,
/// so the entire annotation pipeline, formatters, and all downstream code
/// remain unchanged.
pub fn parse_pdb(path: &Path, debug_file: &str, debug_id: &str) -> Result<SymFile> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("opening PDB file: {}", path.display()))?;
    let mut pdb = pdb::PDB::open(file).context("parsing PDB file")?;

    // 1. Machine type → architecture string
    let arch = {
        let dbi = pdb
            .debug_information()
            .context("reading PDB debug information")?;
        match dbi.machine_type() {
            Ok(pdb::MachineType::Amd64) => "x86_64",
            Ok(pdb::MachineType::X86) => "x86",
            Ok(pdb::MachineType::Arm64) => "aarch64",
            Ok(pdb::MachineType::Arm | pdb::MachineType::ArmNT) => "arm",
            Ok(other) => bail!("unsupported PDB machine type: {:?}", other),
            Err(e) => bail!("cannot read PDB machine type: {e}"),
        }
    };

    // 2. Address map for section:offset → RVA conversion
    let address_map = pdb.address_map().context("reading PDB address map")?;

    // 3. String table (needed for file name resolution in line programs).
    // Some PDBs (especially newer Windows kernel modules) lack a string table;
    // we still extract functions/publics/inlines, just without source lines.
    let string_table = pdb.string_table().ok();

    // 4. Public symbols
    let mut publics: Vec<PublicRecord> = Vec::new();
    {
        let global_symbols = pdb.global_symbols().context("reading PDB global symbols")?;
        let mut iter = global_symbols.iter();
        while let Some(symbol) = iter.next().context("iterating global symbols")? {
            if let Ok(pdb::SymbolData::Public(data)) = symbol.parse() {
                if let Some(rva) = data.offset.to_rva(&address_map) {
                    publics.push(PublicRecord {
                        address: u64::from(rva.0),
                        param_size: 0,
                        name: data.name.to_string().into_owned(),
                    });
                }
            }
        }
    }

    // 5. Build inlinee name map from the ID information (IPI) stream.
    //    Each InlineSiteSymbol references an IdIndex; this maps those to names.
    //    The borrow on `pdb` is released when the block ends.
    let inlinee_names: HashMap<u32, String> = match pdb.id_information() {
        Ok(id_info) => {
            let mut names = HashMap::new();
            let mut iter = id_info.iter();
            while let Ok(Some(item)) = iter.next() {
                match item.parse() {
                    Ok(pdb::IdData::Function(f)) => {
                        names.insert(item.index().0, f.name.to_string().into_owned());
                    }
                    Ok(pdb::IdData::MemberFunction(f)) => {
                        names.insert(item.index().0, f.name.to_string().into_owned());
                    }
                    _ => {}
                }
            }
            names
        }
        Err(_) => HashMap::new(),
    };

    // 6. Parse srcsrv stream for build path → VCS path mapping.
    //    Mozilla PDB files contain an srcsrv stream mapping raw build paths
    //    (e.g. /builds/worker/checkouts/gecko/...) to VCS paths (hg:..., git:...).
    let srcsrv_map: HashMap<String, String> = match pdb.named_stream(b"srcsrv") {
        Ok(stream) => parse_srcsrv_stream(stream.as_slice()),
        Err(_) => HashMap::new(),
    };

    // 7. Per-module iteration: procedures, inline sites, and line programs
    let mut files: Vec<String> = Vec::new();
    let mut file_intern: HashMap<String, usize> = HashMap::new();
    let mut inline_origins: Vec<String> = Vec::new();
    let mut origin_intern: HashMap<String, usize> = HashMap::new();
    let mut functions: Vec<FuncRecord> = Vec::new();

    let dbi = pdb
        .debug_information()
        .context("reading PDB debug information (modules)")?;
    let mut modules = dbi.modules().context("reading PDB modules")?;

    // Suppress panic messages from the `pdb` crate during module processing.
    // Some PDB modules trigger assertion failures that we catch and skip.
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    while let Some(module) = modules.next().context("iterating PDB modules")? {
        // The `pdb` crate may panic on certain modules (e.g. assertion failures
        // in symbol/line iteration for some complex PDBs like xul.pdb). We catch
        // these panics and skip the affected module rather than crashing.
        let module_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let module_info = match pdb.module_info(&module) {
                Ok(Some(info)) => info,
                Ok(None) => return Ok((Vec::new(), Vec::new())),
                Err(_) => return Ok((Vec::new(), Vec::new())),
            };

            // Scope stack for tracking Procedure → InlineSite nesting.
            struct ScopeEntry {
                end_offset: u32,
                depth: i32,      // -1 for Procedure, 0+ for InlineSite
                func_idx: usize, // index into module_procs
                proc_offset: pdb::PdbInternalSectionOffset,
            }

            let mut module_procs: Vec<FuncRecord> = Vec::new();
            let mut extra_pubs: Vec<PublicRecord> = Vec::new();
            {
                let mut symbols = module_info.symbols()?;
                let mut scope_stack: Vec<ScopeEntry> = Vec::new();

                while let Some(symbol) = symbols.next()? {
                    let sym_offset = symbol.index().0;

                    // Pop expired scopes
                    while scope_stack
                        .last()
                        .is_some_and(|s| sym_offset >= s.end_offset)
                    {
                        scope_stack.pop();
                    }

                    match symbol.parse() {
                        Ok(pdb::SymbolData::Procedure(proc_data)) => {
                            if let Some(rva) = proc_data.offset.to_rva(&address_map) {
                                let size = u64::from(proc_data.len);
                                if size == 0 {
                                    extra_pubs.push(PublicRecord {
                                        address: u64::from(rva.0),
                                        param_size: 0,
                                        name: proc_data.name.to_string().into_owned(),
                                    });
                                } else {
                                    let func_idx = module_procs.len();
                                    module_procs.push(FuncRecord {
                                        address: u64::from(rva.0),
                                        size,
                                        param_size: 0,
                                        name: proc_data.name.to_string().into_owned(),
                                        lines: Vec::new(),
                                        inlines: Vec::new(),
                                    });
                                    scope_stack.push(ScopeEntry {
                                        end_offset: proc_data.end.0,
                                        depth: -1,
                                        func_idx,
                                        proc_offset: proc_data.offset,
                                    });
                                }
                            }
                        }
                        Ok(pdb::SymbolData::InlineSite(site)) => {
                            if let Some(parent) = scope_stack.last() {
                                let depth = (parent.depth + 1) as u32;
                                let func_idx = parent.func_idx;
                                let proc_offset = parent.proc_offset;

                                // Resolve inlinee name from the IPI stream
                                let name = inlinee_names
                                    .get(&site.inlinee.0)
                                    .cloned()
                                    .unwrap_or_else(|| format!("<inline #{}>", site.inlinee.0));

                                // Intern the origin name
                                let origin_idx = if let Some(&idx) = origin_intern.get(&name) {
                                    idx
                                } else {
                                    let idx = inline_origins.len();
                                    inline_origins.push(name.clone());
                                    origin_intern.insert(name, idx);
                                    idx
                                };

                                // Extract code ranges from binary annotations
                                let ranges = extract_inline_ranges(
                                    &site.annotations,
                                    proc_offset,
                                    &address_map,
                                );

                                if !ranges.is_empty() {
                                    module_procs[func_idx].inlines.push(InlineRecord {
                                        depth,
                                        call_line: 0,
                                        call_file_index: usize::MAX,
                                        origin_index: origin_idx,
                                        ranges,
                                    });
                                }

                                scope_stack.push(ScopeEntry {
                                    end_offset: site.end.0,
                                    depth: depth as i32,
                                    func_idx,
                                    proc_offset,
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }

            if module_procs.is_empty() {
                return Ok((module_procs, extra_pubs));
            }

            // Sort module procedures by address for binary search
            module_procs.sort_by_key(|f| f.address);

            // Collect line information from this module's line program.
            // Requires string_table to resolve file names.
            let string_table = match &string_table {
                Some(st) => st,
                None => return Ok((module_procs, extra_pubs)),
            };
            let line_program = match module_info.line_program() {
                Ok(program) => program,
                Err(_) => return Ok((module_procs, extra_pubs)),
            };

            let mut line_iter = line_program.lines();
            while let Some(line_info) = line_iter.next()? {
                if let Some(rva) = line_info.offset.to_rva(&address_map) {
                    let addr = u64::from(rva.0);
                    let line_num = line_info.line_start;

                    // Resolve file name, mapping build paths to VCS paths via srcsrv
                    let file_info = line_program.get_file_info(line_info.file_index)?;
                    let raw_name = string_table.get(file_info.name)?.to_string().into_owned();
                    let file_name = srcsrv_map
                        .get(&raw_name.replace('\\', "/"))
                        .cloned()
                        .unwrap_or(raw_name);

                    // Intern the file name
                    let file_idx = if let Some(&idx) = file_intern.get(&file_name) {
                        idx
                    } else {
                        let idx = files.len();
                        files.push(file_name.clone());
                        file_intern.insert(file_name, idx);
                        idx
                    };

                    // Find enclosing function via binary search
                    let proc_idx = module_procs.partition_point(|f| f.address <= addr);
                    if proc_idx > 0 {
                        let func = &module_procs[proc_idx - 1];
                        if addr < func.address + func.size {
                            module_procs[proc_idx - 1].lines.push(LineRecord {
                                address: addr,
                                size: 0, // placeholder
                                line: line_num,
                                file_index: file_idx,
                            });
                        }
                    }
                }
            }

            Ok::<_, pdb::Error>((module_procs, extra_pubs))
        }));

        match module_result {
            Ok(Ok((procs, extra_pubs))) => {
                publics.extend(extra_pubs);
                functions.extend(procs);
            }
            Ok(Err(_)) | Err(_) => {
                // Module processing failed or panicked — skip it
                continue;
            }
        }
    }

    // Restore the original panic hook
    std::panic::set_hook(prev_hook);

    // Compute line record sizes: each line extends to the start of the next line
    // (or to the end of the function for the last line)
    for func in &mut functions {
        func.lines.sort_by_key(|l| l.address);
        func.lines.dedup_by_key(|l| l.address);
        let n = func.lines.len();
        for i in 0..n {
            let end = if i + 1 < n {
                func.lines[i + 1].address
            } else {
                func.address + func.size
            };
            func.lines[i].size = end - func.lines[i].address;
        }
    }

    // Enrich function names with mangled names from public symbols.
    // Public symbols carry MSVC-mangled names (starting with '?') that encode
    // parameter types. Replacing the short procedure name with the mangled form
    // lets the demangler produce full signatures at display time.
    {
        let mangled_names: HashMap<u64, &str> = publics
            .iter()
            .filter(|p| p.name.starts_with('?'))
            .map(|p| (p.address, p.name.as_str()))
            .collect();
        for func in &mut functions {
            if let Some(&mangled) = mangled_names.get(&func.address) {
                func.name = mangled.to_string();
            }
        }
    }

    // Resolve inline call sites from parent function's line records.
    // For each inline, find the parent's source line at the inline's start
    // address — that's where the inline call was made from.
    for func in &mut functions {
        for inline in &mut func.inlines {
            if let Some(&(start_addr, _)) = inline.ranges.first() {
                let line_idx = func.lines.partition_point(|l| l.address <= start_addr);
                if line_idx > 0 {
                    let line = &func.lines[line_idx - 1];
                    if start_addr < line.address + line.size {
                        inline.call_file_index = line.file_index;
                        inline.call_line = line.line;
                    }
                }
            }
        }
    }

    // Build the SymFile
    let module = ModuleRecord {
        os: "windows".to_string(),
        arch: arch.to_string(),
        debug_id: debug_id.to_string(),
        name: debug_file.to_string(),
    };

    Ok(SymFile::from_parts(
        module,
        files,
        functions,
        publics,
        inline_origins,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_line_size_computation() {
        // Simulate what parse_pdb does for line size computation
        let mut lines = vec![
            LineRecord {
                address: 0x1000,
                size: 0,
                line: 10,
                file_index: 0,
            },
            LineRecord {
                address: 0x1010,
                size: 0,
                line: 11,
                file_index: 0,
            },
            LineRecord {
                address: 0x1030,
                size: 0,
                line: 12,
                file_index: 0,
            },
        ];
        let func_end = 0x1050;

        lines.sort_by_key(|l| l.address);
        let n = lines.len();
        for i in 0..n {
            let end = if i + 1 < n {
                lines[i + 1].address
            } else {
                func_end
            };
            lines[i].size = end - lines[i].address;
        }

        assert_eq!(lines[0].size, 0x10);
        assert_eq!(lines[1].size, 0x20);
        assert_eq!(lines[2].size, 0x20);
    }

    #[test]
    fn test_from_parts_sorts_and_indexes() {
        let module = ModuleRecord {
            os: "windows".to_string(),
            arch: "x86_64".to_string(),
            debug_id: "TEST123".to_string(),
            name: "test.pdb".to_string(),
        };

        // Functions in reverse order to verify sorting
        let functions = vec![
            FuncRecord {
                address: 0x2000,
                size: 0x40,
                param_size: 0,
                name: "SecondFunc".to_string(),
                lines: Vec::new(),
                inlines: Vec::new(),
            },
            FuncRecord {
                address: 0x1000,
                size: 0x80,
                param_size: 0,
                name: "FirstFunc".to_string(),
                lines: vec![
                    LineRecord {
                        address: 0x1020,
                        size: 0x10,
                        line: 11,
                        file_index: 0,
                    },
                    LineRecord {
                        address: 0x1000,
                        size: 0x20,
                        line: 10,
                        file_index: 0,
                    },
                ],
                inlines: Vec::new(),
            },
        ];

        let publics = vec![
            PublicRecord {
                address: 0x4000,
                param_size: 0,
                name: "Pub2".to_string(),
            },
            PublicRecord {
                address: 0x3000,
                param_size: 0,
                name: "Pub1".to_string(),
            },
        ];

        let sym = SymFile::from_parts(
            module,
            vec!["test.cpp".to_string()],
            functions,
            publics,
            Vec::new(),
        );

        // Functions should be sorted by address
        assert_eq!(sym.functions[0].name, "FirstFunc");
        assert_eq!(sym.functions[1].name, "SecondFunc");

        // Lines within FirstFunc should be sorted
        assert_eq!(sym.functions[0].lines[0].address, 0x1000);
        assert_eq!(sym.functions[0].lines[1].address, 0x1020);

        // Publics should be sorted
        assert_eq!(sym.publics[0].name, "Pub1");
        assert_eq!(sym.publics[1].name, "Pub2");

        // Name index should work
        assert!(sym.find_function_by_name("FirstFunc").is_some());
        assert!(sym.find_function_by_name("SecondFunc").is_some());
        assert!(sym.find_function_by_name("NonExistent").is_none());
    }

    #[test]
    fn test_from_parts_preserves_inline_data() {
        let module = ModuleRecord {
            os: "windows".to_string(),
            arch: "x86_64".to_string(),
            debug_id: "TEST123".to_string(),
            name: "test.pdb".to_string(),
        };

        let functions = vec![FuncRecord {
            address: 0x1000,
            size: 0x100,
            param_size: 0,
            name: "MyFunc".to_string(),
            lines: Vec::new(),
            inlines: vec![
                InlineRecord {
                    depth: 0,
                    call_line: 0,
                    call_file_index: usize::MAX,
                    origin_index: 0,
                    ranges: vec![(0x1020, 0x30)],
                },
                InlineRecord {
                    depth: 1,
                    call_line: 0,
                    call_file_index: usize::MAX,
                    origin_index: 1,
                    ranges: vec![(0x1030, 0x10)],
                },
            ],
        }];

        let inline_origins = vec!["HelperFunc".to_string(), "NestedHelper".to_string()];

        let sym = SymFile::from_parts(module, Vec::new(), functions, Vec::new(), inline_origins);

        let func = sym.find_function_by_name("MyFunc").unwrap();
        assert_eq!(func.inlines.len(), 2);

        // Test get_inline_at for depth-0 inline
        let inlines = sym.get_inline_at(0x1020, func);
        assert_eq!(inlines.len(), 1);
        assert_eq!(inlines[0].name, "HelperFunc");
        assert_eq!(inlines[0].depth, 0);
        assert!(inlines[0].call_file.is_none()); // usize::MAX → no file

        // Test get_inline_at for nested inline (both depth 0 and 1 active)
        let inlines = sym.get_inline_at(0x1030, func);
        assert_eq!(inlines.len(), 2);
        assert_eq!(inlines[0].name, "HelperFunc");
        assert_eq!(inlines[0].depth, 0);
        assert_eq!(inlines[1].name, "NestedHelper");
        assert_eq!(inlines[1].depth, 1);

        // Test get_inline_at outside inline ranges
        let inlines = sym.get_inline_at(0x1000, func);
        assert!(inlines.is_empty());
    }

    #[test]
    fn test_extract_inline_ranges_basic() {
        // Mock a simple PdbInternalSectionOffset → RVA mapping
        // We can't call extract_inline_ranges without a real AddressMap,
        // but we can verify the logic through from_parts + get_inline_at
        let module = ModuleRecord {
            os: "windows".to_string(),
            arch: "x86_64".to_string(),
            debug_id: "TEST".to_string(),
            name: "test.pdb".to_string(),
        };

        // Simulate what extract_inline_ranges would produce
        let functions = vec![FuncRecord {
            address: 0x5000,
            size: 0x200,
            param_size: 0,
            name: "BigFunc".to_string(),
            lines: Vec::new(),
            inlines: vec![InlineRecord {
                depth: 0,
                call_line: 0,
                call_file_index: usize::MAX,
                origin_index: 0,
                ranges: vec![(0x5010, 0x20), (0x5080, 0x40)],
            }],
        }];

        let sym = SymFile::from_parts(
            module,
            Vec::new(),
            functions,
            Vec::new(),
            vec!["MultiRangeInline".to_string()],
        );

        let func = sym.find_function_by_name("BigFunc").unwrap();

        // First range
        let inlines = sym.get_inline_at(0x5010, func);
        assert_eq!(inlines.len(), 1);
        assert_eq!(inlines[0].name, "MultiRangeInline");

        // Between ranges — not active
        let inlines = sym.get_inline_at(0x5050, func);
        assert!(inlines.is_empty());

        // Second range
        let inlines = sym.get_inline_at(0x50A0, func);
        assert_eq!(inlines.len(), 1);
        assert_eq!(inlines[0].name, "MultiRangeInline");

        // After all ranges
        let inlines = sym.get_inline_at(0x50C0, func);
        assert!(inlines.is_empty());
    }

    #[test]
    fn test_origin_interning_deduplication() {
        // Verify that shared origin names produce the same origin_index
        let module = ModuleRecord {
            os: "windows".to_string(),
            arch: "x86_64".to_string(),
            debug_id: "TEST".to_string(),
            name: "test.pdb".to_string(),
        };

        let functions = vec![
            FuncRecord {
                address: 0x1000,
                size: 0x100,
                param_size: 0,
                name: "Func1".to_string(),
                lines: Vec::new(),
                inlines: vec![InlineRecord {
                    depth: 0,
                    call_line: 0,
                    call_file_index: usize::MAX,
                    origin_index: 0, // "SharedHelper"
                    ranges: vec![(0x1010, 0x20)],
                }],
            },
            FuncRecord {
                address: 0x2000,
                size: 0x100,
                param_size: 0,
                name: "Func2".to_string(),
                lines: Vec::new(),
                inlines: vec![InlineRecord {
                    depth: 0,
                    call_line: 0,
                    call_file_index: usize::MAX,
                    origin_index: 0, // same "SharedHelper"
                    ranges: vec![(0x2010, 0x30)],
                }],
            },
        ];

        let sym = SymFile::from_parts(
            module,
            Vec::new(),
            functions,
            Vec::new(),
            vec!["SharedHelper".to_string()],
        );

        // Both functions should resolve the same inline origin name
        let func1 = sym.find_function_by_name("Func1").unwrap();
        let inlines1 = sym.get_inline_at(0x1010, func1);
        assert_eq!(inlines1[0].name, "SharedHelper");

        let func2 = sym.find_function_by_name("Func2").unwrap();
        let inlines2 = sym.get_inline_at(0x2010, func2);
        assert_eq!(inlines2[0].name, "SharedHelper");
    }

    #[test]
    fn test_parse_srcsrv_hg_target() {
        let srcsrv = b"SRCSRV: ini ------------------------------------------------\r\n\
            VERSION=2\r\n\
            SRCSRV: variables ------------------------------------------\r\n\
            HGSERVER=https://hg.mozilla.org/releases/mozilla-esr140\r\n\
            HG_TARGET=%hgserver%/raw-file/%var4%/%var3%\r\n\
            SRCSRV: source files ---------------------------------------\r\n\
            /builds/worker/checkouts/gecko/dom/base/Element.cpp*HG_TARGET*dom/base/Element.cpp*abc123def456\r\n\
            /builds/worker/checkouts/gecko/gfx/layers/Compositor.cpp*HG_TARGET*gfx/layers/Compositor.cpp*abc123def456\r\n\
            SRCSRV: end ------------------------------------------------\r\n";

        let map = parse_srcsrv_stream(srcsrv);
        assert_eq!(
            map.get("/builds/worker/checkouts/gecko/dom/base/Element.cpp")
                .unwrap(),
            "hg:hg.mozilla.org/releases/mozilla-esr140:dom/base/Element.cpp:abc123def456"
        );
        assert_eq!(
            map.get("/builds/worker/checkouts/gecko/gfx/layers/Compositor.cpp")
                .unwrap(),
            "hg:hg.mozilla.org/releases/mozilla-esr140:gfx/layers/Compositor.cpp:abc123def456"
        );
    }

    #[test]
    fn test_parse_srcsrv_rust_github() {
        let srcsrv = b"SRCSRV: ini ------------------------------------------------\r\n\
            VERSION=2\r\n\
            SRCSRV: variables ------------------------------------------\r\n\
            RUST_GITHUB_TARGET=https://github.com/rust-lang/rust/raw/%var4%/%var3%\r\n\
            SRCSRV: source files ---------------------------------------\r\n\
            /rustc/abc123/library/core/src/fmt/mod.rs*RUST_GITHUB_TARGET*library/core/src/fmt/mod.rs*abc123\r\n\
            SRCSRV: end ------------------------------------------------\r\n";

        let map = parse_srcsrv_stream(srcsrv);
        assert_eq!(
            map.get("/rustc/abc123/library/core/src/fmt/mod.rs")
                .unwrap(),
            "git:github.com/rust-lang/rust:library/core/src/fmt/mod.rs:abc123"
        );
    }

    #[test]
    fn test_parse_srcsrv_s3_skipped() {
        let srcsrv = b"SRCSRV: ini ------------------------------------------------\r\n\
            VERSION=2\r\n\
            SRCSRV: variables ------------------------------------------\r\n\
            S3_BUCKET=gecko-generated-sources\r\n\
            S3_TARGET=https://%s3_bucket%.s3.amazonaws.com/%var3%\r\n\
            SRCSRV: source files ---------------------------------------\r\n\
            /builds/worker/workspace/obj-build/some/generated.cpp*S3_TARGET*hash123/some/generated.cpp*\r\n\
            SRCSRV: end ------------------------------------------------\r\n";

        let map = parse_srcsrv_stream(srcsrv);
        assert!(map.is_empty());
    }

    #[test]
    fn test_parse_srcsrv_empty() {
        assert!(parse_srcsrv_stream(b"").is_empty());
        assert!(parse_srcsrv_stream(&[0xff, 0xfe]).is_empty());
    }

    #[test]
    fn test_parse_srcsrv_mixed_targets() {
        let srcsrv = b"SRCSRV: ini ------------------------------------------------\r\n\
            VERSION=2\r\n\
            SRCSRV: variables ------------------------------------------\r\n\
            HGSERVER=https://hg.mozilla.org/releases/mozilla-esr140\r\n\
            HG_TARGET=%hgserver%/raw-file/%var4%/%var3%\r\n\
            RUST_GITHUB_TARGET=https://github.com/rust-lang/rust/raw/%var4%/%var3%\r\n\
            S3_BUCKET=gecko-generated-sources\r\n\
            S3_TARGET=https://%s3_bucket%.s3.amazonaws.com/%var3%\r\n\
            SRCSRV: source files ---------------------------------------\r\n\
            /builds/worker/checkouts/gecko/xpcom/base/nsDebugImpl.cpp*HG_TARGET*xpcom/base/nsDebugImpl.cpp*aaa111\r\n\
            /rustc/bbb222/library/std/src/io/mod.rs*RUST_GITHUB_TARGET*library/std/src/io/mod.rs*bbb222\r\n\
            /builds/worker/workspace/obj-build/gen/file.cpp*S3_TARGET*hash/gen/file.cpp*\r\n\
            SRCSRV: end ------------------------------------------------\r\n";

        let map = parse_srcsrv_stream(srcsrv);
        // HG entry mapped
        assert_eq!(
            map.get("/builds/worker/checkouts/gecko/xpcom/base/nsDebugImpl.cpp")
                .unwrap(),
            "hg:hg.mozilla.org/releases/mozilla-esr140:xpcom/base/nsDebugImpl.cpp:aaa111"
        );
        // Rust entry mapped
        assert_eq!(
            map.get("/rustc/bbb222/library/std/src/io/mod.rs").unwrap(),
            "git:github.com/rust-lang/rust:library/std/src/io/mod.rs:bbb222"
        );
        // S3 entry NOT mapped
        assert!(!map.contains_key("/builds/worker/workspace/obj-build/gen/file.cpp"));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_resolve_srcsrv_vars_basic() {
        let mut vars = HashMap::new();
        vars.insert(
            "HGSERVER".to_string(),
            "https://hg.mozilla.org/releases/mozilla-esr140".to_string(),
        );

        let result = resolve_srcsrv_vars("%hgserver%/raw-file/%var4%/%var3%", &vars);
        assert_eq!(
            result,
            "https://hg.mozilla.org/releases/mozilla-esr140/raw-file/%var4%/%var3%"
        );
    }

    #[test]
    fn test_resolve_srcsrv_vars_no_vars() {
        let vars = HashMap::new();
        let result =
            resolve_srcsrv_vars("https://github.com/rust-lang/rust/raw/%var4%/%var3%", &vars);
        assert_eq!(
            result,
            "https://github.com/rust-lang/rust/raw/%var4%/%var3%"
        );
    }

    #[test]
    fn test_extract_vcs_prefix_hg() {
        let url = "https://hg.mozilla.org/releases/mozilla-esr140/raw-file/%var4%/%var3%";
        assert_eq!(
            extract_vcs_prefix(url).unwrap(),
            "hg:hg.mozilla.org/releases/mozilla-esr140"
        );
    }

    #[test]
    fn test_extract_vcs_prefix_github() {
        let url = "https://github.com/rust-lang/rust/raw/%var4%/%var3%";
        assert_eq!(
            extract_vcs_prefix(url).unwrap(),
            "git:github.com/rust-lang/rust"
        );
    }

    #[test]
    fn test_extract_vcs_prefix_s3_none() {
        let url = "https://gecko-generated-sources.s3.amazonaws.com/%var3%";
        assert!(extract_vcs_prefix(url).is_none());
    }

    #[test]
    fn test_parse_srcsrv_backslash_paths() {
        let srcsrv = b"SRCSRV: ini ------------------------------------------------\r\n\
            VERSION=2\r\n\
            SRCSRV: variables ------------------------------------------\r\n\
            HGSERVER=https://hg.mozilla.org/releases/mozilla-esr140\r\n\
            HG_TARGET=%hgserver%/raw-file/%var4%/%var3%\r\n\
            SRCSRV: source files ---------------------------------------\r\n\
            D:\\builds\\worker\\gecko\\dom\\Element.cpp*HG_TARGET*dom/Element.cpp*abc123\r\n\
            SRCSRV: end ------------------------------------------------\r\n";

        let map = parse_srcsrv_stream(srcsrv);
        // Backslashes in build path should be normalized to forward slashes
        assert_eq!(
            map.get("D:/builds/worker/gecko/dom/Element.cpp").unwrap(),
            "hg:hg.mozilla.org/releases/mozilla-esr140:dom/Element.cpp:abc123"
        );
    }
}
