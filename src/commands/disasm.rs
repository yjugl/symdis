// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::io::BufReader;
use std::path::Path;

use anyhow::{Result, Context, bail};

use super::{Cli, DisasmArgs, SyntaxArg};
use crate::binary::{BinaryFile, CpuArch};
use crate::binary::pe::PeFile;
use crate::cache::Cache;
use crate::config::Syntax;
use crate::disasm::annotate;
use crate::disasm::engine::Disassembler;
use crate::fetch;
use crate::output::json;
use crate::output::text::{self, DataSource, FunctionInfo, ModuleInfo};
use super::FormatArg;
use crate::symbols::breakpad::SymFile;

/// Parse a hex offset string (with or without 0x prefix) to u64.
fn parse_offset(s: &str) -> Result<u64> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u64::from_str_radix(s, 16).context("invalid hex offset")
}

pub async fn run(args: &DisasmArgs, cli: &Cli) -> Result<()> {
    let cache = Cache::new(cli.cache_dir.as_ref().map(Path::new))?;
    let client = fetch::build_http_client()?;

    let syntax = match args.syntax {
        SyntaxArg::Intel => Syntax::Intel,
        SyntaxArg::Att => Syntax::Att,
    };

    let highlight_offset = args
        .highlight_offset
        .as_deref()
        .map(parse_offset)
        .transpose()?;

    // Fetch .sym file and binary concurrently
    let sym_fut = fetch::fetch_sym_file(&client, &cache, &args.debug_file, &args.debug_id);
    let bin_fut = async {
        if let (Some(code_file), Some(code_id)) = (&args.code_file, &args.code_id) {
            fetch::fetch_binary(&client, &cache, code_file, code_id).await
        } else {
            // Without code_file/code_id, we can try using the debug_file as code_file
            // and debug_id as code_id (works for some cases like when Tecken proxies to MS)
            let code_file = derive_code_file(&args.debug_file);
            fetch::fetch_binary(&client, &cache, &code_file, &args.debug_id).await
        }
    };

    let (sym_result, bin_result) = tokio::join!(sym_fut, bin_fut);

    // Parse .sym file if available
    let sym_file = match &sym_result {
        Ok(path) => {
            let file = std::fs::File::open(path)
                .with_context(|| format!("opening sym file: {}", path.display()))?;
            let reader = BufReader::new(file);
            match SymFile::parse(reader) {
                Ok(sym) => Some(sym),
                Err(e) => {
                    eprintln!("warning: failed to parse sym file: {e}");
                    None
                }
            }
        }
        Err(e) => {
            eprintln!("warning: sym file not available: {e}");
            None
        }
    };

    // Parse binary if available
    let pe_file = match &bin_result {
        Ok(path) => {
            match PeFile::load(path) {
                Ok(pe) => Some(pe),
                Err(e) => {
                    eprintln!("warning: failed to parse binary: {e}");
                    None
                }
            }
        }
        Err(e) => {
            eprintln!("warning: binary not available: {e}");
            None
        }
    };

    // Determine architecture
    let arch = determine_arch(&sym_file, &pe_file)?;

    // Find the target function
    let (func_name, func_addr, func_size) = find_target(args, &sym_file, &pe_file)?;

    // Look up the FuncRecord for annotation (re-lookup by address)
    let func_record = sym_file
        .as_ref()
        .and_then(|sym| sym.find_function_at_address(func_addr));

    // Derive the function's primary source file from the first line record
    let source_file = sym_file.as_ref().and_then(|sym| {
        func_record.and_then(|func| {
            func.lines
                .first()
                .and_then(|lr| sym.files.get(lr.file_index).cloned())
        })
    });

    // Build module info for output
    let module_info = ModuleInfo {
        debug_file: args.debug_file.clone(),
        debug_id: args.debug_id.clone(),
        code_file: args.code_file.clone(),
        arch: arch.to_string(),
    };

    let function_info = FunctionInfo {
        name: func_name,
        address: func_addr,
        size: func_size,
        source_file,
    };

    // Disassemble if binary is available
    if let Some(pe) = &pe_file {
        let code = pe.extract_code(func_addr, func_size)
            .context("extracting code from binary")?;

        let disassembler = Disassembler::new(arch, syntax)?;
        let instructions = disassembler.disassemble(&code, func_addr, args.max_instructions)?;

        // Run annotation pipeline
        let annotated = annotate::annotate(
            instructions,
            sym_file.as_ref(),
            func_record,
            Some(pe as &dyn BinaryFile),
            highlight_offset,
        );

        let data_source = if sym_file.is_some() {
            DataSource::BinaryAndSym
        } else {
            DataSource::BinaryOnly
        };

        match cli.format {
            FormatArg::Text => {
                let output = text::format_text(&module_info, &function_info, &annotated, &data_source);
                print!("{output}");
            }
            FormatArg::Json => {
                let output = json::format_json(&module_info, &function_info, &annotated, &data_source);
                println!("{output}");
            }
        }
    } else if sym_file.is_some() {
        // Sym only - no binary available
        match cli.format {
            FormatArg::Text => {
                let output = text::format_sym_only(&module_info, &function_info);
                print!("{output}");
            }
            FormatArg::Json => {
                let output = json::format_json_sym_only(&module_info, &function_info);
                println!("{output}");
            }
        }
    } else {
        match cli.format {
            FormatArg::Text => {
                bail!(
                    "neither symbol file nor binary available for {}/{}",
                    args.debug_file,
                    args.debug_id
                );
            }
            FormatArg::Json => {
                let msg = format!(
                    "neither symbol file nor binary available for {}/{}",
                    args.debug_file, args.debug_id
                );
                let output = json::format_json_error(&msg);
                println!("{output}");
                return Ok(());
            }
        }
    }

    Ok(())
}

/// Derive a code file name from a debug file name.
/// xul.pdb -> xul.dll, ntdll.pdb -> ntdll.dll, firefox.pdb -> firefox.exe
fn derive_code_file(debug_file: &str) -> String {
    if let Some(stem) = debug_file.strip_suffix(".pdb") {
        if stem.eq_ignore_ascii_case("firefox") {
            format!("{stem}.exe")
        } else {
            format!("{stem}.dll")
        }
    } else {
        debug_file.to_string()
    }
}

/// Determine the CPU architecture from available sources.
fn determine_arch(
    sym_file: &Option<SymFile>,
    pe_file: &Option<PeFile>,
) -> Result<CpuArch> {
    // Try sym file first
    if let Some(sym) = sym_file {
        if let Some(arch) = CpuArch::from_sym_arch(&sym.module.arch) {
            return Ok(arch);
        }
    }

    // Try PE file
    if let Some(pe) = pe_file {
        return Ok(pe.arch());
    }

    bail!("cannot determine architecture: no sym file or binary available")
}

/// Find the target function by name or offset.
fn find_target(
    args: &DisasmArgs,
    sym_file: &Option<SymFile>,
    pe_file: &Option<PeFile>,
) -> Result<(String, u64, u64)> {
    if let Some(ref name) = args.function {
        find_by_name(name, args.fuzzy, sym_file, pe_file)
    } else if let Some(ref offset_str) = args.offset {
        let offset = parse_offset(offset_str)?;
        find_by_offset(offset, sym_file, pe_file)
    } else {
        bail!("either --function or --offset must be specified")
    }
}

fn find_by_name(
    name: &str,
    fuzzy: bool,
    sym_file: &Option<SymFile>,
    pe_file: &Option<PeFile>,
) -> Result<(String, u64, u64)> {
    if let Some(sym) = sym_file {
        if fuzzy {
            let matches = sym.find_function_by_name_fuzzy(name);
            match matches.len() {
                0 => {}
                1 => {
                    let func = matches[0];
                    return Ok((func.name.clone(), func.address, func.size));
                }
                _ => {
                    let mut msg = format!("ambiguous function name '{name}'. Matches:\n");
                    for (i, f) in matches.iter().enumerate().take(20) {
                        msg.push_str(&format!(
                            "  {}. {} (RVA: 0x{:x}, size: 0x{:x})\n",
                            i + 1,
                            f.name,
                            f.address,
                            f.size
                        ));
                    }
                    if matches.len() > 20 {
                        msg.push_str(&format!("  ... and {} more\n", matches.len() - 20));
                    }
                    bail!("{msg}");
                }
            }
        }

        // Exact match
        if let Some(func) = sym.find_function_by_name(name) {
            return Ok((func.name.clone(), func.address, func.size));
        }

        // If not exact match and not fuzzy, try fuzzy for a helpful error
        let suggestions = sym.find_function_by_name_fuzzy(name);
        if !suggestions.is_empty() {
            let mut msg = format!("function '{name}' not found. Similar names:\n");
            for f in suggestions.iter().take(10) {
                msg.push_str(&format!("  - {} (0x{:x})\n", f.name, f.address));
            }
            bail!("{msg}");
        }
    }

    // Try PE exports
    if let Some(pe) = pe_file {
        for &(rva, ref exp_name) in pe.exports() {
            if exp_name == name {
                // Estimate size from next export
                let size = estimate_export_size(pe.exports(), rva);
                return Ok((exp_name.clone(), rva, size));
            }
        }
    }

    bail!("function '{name}' not found in symbol file or binary exports")
}

fn find_by_offset(
    offset: u64,
    sym_file: &Option<SymFile>,
    pe_file: &Option<PeFile>,
) -> Result<(String, u64, u64)> {
    // Try sym file first
    if let Some(sym) = sym_file {
        if let Some(func) = sym.find_function_at_address(offset) {
            return Ok((func.name.clone(), func.address, func.size));
        }
        // Try PUBLIC symbols
        if let Some(public) = sym.find_public_at_address(offset) {
            // For PUBLIC symbols, estimate size from next symbol
            let size = estimate_public_size(&sym.publics, public.address);
            return Ok((public.name.clone(), public.address, size));
        }
    }

    // Try PE exports
    if let Some(pe) = pe_file {
        let exports = pe.exports();
        // Find the export at or just before the offset
        let idx = exports.partition_point(|(rva, _)| *rva <= offset);
        if idx > 0 {
            let (rva, name) = &exports[idx - 1];
            let size = estimate_export_size(exports, *rva);
            return Ok((name.clone(), *rva, size));
        }
    }

    bail!("no function found at offset 0x{:x}", offset)
}

/// Estimate function size from the distance to the next export, capped at 64KB.
fn estimate_export_size(exports: &[(u64, String)], rva: u64) -> u64 {
    const MAX_ESTIMATED_SIZE: u64 = 0x10000;
    let idx = exports.partition_point(|(r, _)| *r <= rva);
    if idx < exports.len() {
        let next_rva = exports[idx].0;
        (next_rva - rva).min(MAX_ESTIMATED_SIZE)
    } else {
        MAX_ESTIMATED_SIZE
    }
}

/// Estimate function size from the distance to the next PUBLIC symbol.
fn estimate_public_size(publics: &[crate::symbols::breakpad::PublicRecord], addr: u64) -> u64 {
    const MAX_ESTIMATED_SIZE: u64 = 0x10000;
    let idx = publics.partition_point(|p| p.address <= addr);
    if idx < publics.len() {
        let next_addr = publics[idx].address;
        (next_addr - addr).min(MAX_ESTIMATED_SIZE)
    } else {
        MAX_ESTIMATED_SIZE
    }
}
