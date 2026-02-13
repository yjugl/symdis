// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Result, Context, bail};
use pdb::FallibleIterator;

use super::breakpad::{
    FuncRecord, LineRecord, ModuleRecord, PublicRecord, SymFile,
};

/// Parse a PDB file and convert it into a SymFile.
///
/// This bridges the `pdb` crate's data model into symdis's SymFile struct,
/// so the entire annotation pipeline, formatters, and all downstream code
/// remain unchanged.
pub fn parse_pdb(path: &Path, debug_file: &str, debug_id: &str) -> Result<SymFile> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("opening PDB file: {}", path.display()))?;
    let mut pdb = pdb::PDB::open(file)
        .context("parsing PDB file")?;

    // 1. Machine type → architecture string
    let arch = {
        let dbi = pdb.debug_information()
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
    let address_map = pdb.address_map()
        .context("reading PDB address map")?;

    // 3. String table (needed for file name resolution in line programs)
    let string_table = pdb.string_table()
        .context("reading PDB string table")?;

    // 4. Public symbols
    let mut publics: Vec<PublicRecord> = Vec::new();
    {
        let global_symbols = pdb.global_symbols()
            .context("reading PDB global symbols")?;
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

    // 5. Per-module iteration: procedures + line programs
    let mut files: Vec<String> = Vec::new();
    let mut file_intern: HashMap<String, usize> = HashMap::new();
    let mut functions: Vec<FuncRecord> = Vec::new();

    let dbi = pdb.debug_information()
        .context("reading PDB debug information (modules)")?;
    let mut modules = dbi.modules()
        .context("reading PDB modules")?;

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

            // Collect procedures from this module
            let mut module_procs: Vec<FuncRecord> = Vec::new();
            let mut extra_pubs: Vec<PublicRecord> = Vec::new();
            {
                let mut symbols = module_info.symbols()?;
                while let Some(symbol) = symbols.next()? {
                    if let Ok(pdb::SymbolData::Procedure(proc_data)) = symbol.parse() {
                        if let Some(rva) = proc_data.offset.to_rva(&address_map) {
                            let size = u64::from(proc_data.len);
                            if size == 0 {
                                extra_pubs.push(PublicRecord {
                                    address: u64::from(rva.0),
                                    param_size: 0,
                                    name: proc_data.name.to_string().into_owned(),
                                });
                            } else {
                                module_procs.push(FuncRecord {
                                    address: u64::from(rva.0),
                                    size,
                                    param_size: 0,
                                    name: proc_data.name.to_string().into_owned(),
                                    lines: Vec::new(),
                                    inlines: Vec::new(),
                                });
                            }
                        }
                    }
                }
            }

            if module_procs.is_empty() {
                return Ok((module_procs, extra_pubs));
            }

            // Sort module procedures by address for binary search
            module_procs.sort_by_key(|f| f.address);

            // Collect line information from this module's line program
            let line_program = match module_info.line_program() {
                Ok(program) => program,
                Err(_) => return Ok((module_procs, extra_pubs)),
            };

            let mut line_iter = line_program.lines();
            while let Some(line_info) = line_iter.next()? {
                if let Some(rva) = line_info.offset.to_rva(&address_map) {
                    let addr = u64::from(rva.0);
                    let line_num = line_info.line_start;

                    // Resolve file name
                    let file_info = line_program.get_file_info(line_info.file_index)?;
                    let file_name = string_table.get(file_info.name)?
                        .to_string()
                        .into_owned();

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

    // Build the SymFile
    let module = ModuleRecord {
        os: "windows".to_string(),
        arch: arch.to_string(),
        debug_id: debug_id.to_string(),
        name: debug_file.to_string(),
    };

    Ok(SymFile::from_parts(module, files, functions, publics, Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_line_size_computation() {
        // Simulate what parse_pdb does for line size computation
        let mut lines = vec![
            LineRecord { address: 0x1000, size: 0, line: 10, file_index: 0 },
            LineRecord { address: 0x1010, size: 0, line: 11, file_index: 0 },
            LineRecord { address: 0x1030, size: 0, line: 12, file_index: 0 },
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
                    LineRecord { address: 0x1020, size: 0x10, line: 11, file_index: 0 },
                    LineRecord { address: 0x1000, size: 0x20, line: 10, file_index: 0 },
                ],
                inlines: Vec::new(),
            },
        ];

        let publics = vec![
            PublicRecord { address: 0x4000, param_size: 0, name: "Pub2".to_string() },
            PublicRecord { address: 0x3000, param_size: 0, name: "Pub1".to_string() },
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
}
