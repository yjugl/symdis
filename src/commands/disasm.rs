// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::io::BufReader;

use anyhow::{Result, Context, bail};
use tracing::warn;

use super::DisasmArgs;
use crate::binary::{BinaryFile, CpuArch};
use crate::demangle::maybe_demangle;
use crate::binary::elf::ElfFile;
use crate::binary::macho::MachOFile;
use crate::binary::pe::PeFile;
use crate::cache::Cache;
use crate::config::{Config, OutputFormat};
use crate::disasm::annotate;
use crate::disasm::engine::Disassembler;
use crate::fetch;
use crate::output::json;
use crate::output::text::{self, DataSource, FunctionInfo, ModuleInfo, SymOnlyData, SymOnlyLine, SymOnlyInline};
use crate::symbols::breakpad::SymFile;

/// Parse a hex offset string (with or without 0x prefix) to u64.
fn parse_offset(s: &str) -> Result<u64> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u64::from_str_radix(s, 16).context("invalid hex offset")
}

pub async fn run(args: &DisasmArgs, config: &Config) -> Result<()> {
    let cache = Cache::new(&config.cache_dir, config.miss_ttl_hours);
    let client = fetch::build_http_client(config)?;

    let highlight_offset = args
        .highlight_offset
        .as_deref()
        .map(parse_offset)
        .transpose()?;

    // Fetch .sym file and binary concurrently
    let sym_fut = fetch::fetch_sym_file(&client, &cache, config, &args.debug_file, &args.debug_id);
    let bin_fut = async {
        if let (Some(code_file), Some(code_id)) = (&args.code_file, &args.code_id) {
            fetch::fetch_binary(&client, &cache, config, code_file, code_id).await
        } else {
            // Without code_file/code_id, we can try using the debug_file as code_file
            // and debug_id as code_id (works for some cases like when Tecken proxies to MS)
            let code_file = derive_code_file(&args.debug_file);
            fetch::fetch_binary(&client, &cache, config, &code_file, &args.debug_id).await
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
                    warn!("failed to parse sym file: {e}");
                    None
                }
            }
        }
        Err(e) => {
            warn!("sym file not available: {e}");
            None
        }
    };

    // If binary fetch failed and sym file indicates Linux, try debuginfod
    let bin_result = match bin_result {
        Ok(path) => Ok(path),
        Err(e) => {
            let is_linux = sym_file.as_ref()
                .map(|sym| sym.module.os.eq_ignore_ascii_case("linux"))
                .unwrap_or_else(|| looks_like_elf(&args.debug_file));
            if is_linux {
                let code_file = args.code_file.as_deref().unwrap_or(&args.debug_file);
                match fetch::fetch_binary_debuginfod(&client, &cache, config, code_file, args.code_id.as_deref(), &args.debug_id).await {
                    Ok(path) => Ok(path),
                    Err(_) => Err(e),
                }
            } else {
                Err(e)
            }
        }
    };

    // If binary still not found and Linux, try Snap Store
    let bin_result = match bin_result {
        Ok(path) => Ok(path),
        Err(e) => {
            let is_linux = sym_file.as_ref()
                .map(|sym| sym.module.os.eq_ignore_ascii_case("linux"))
                .unwrap_or(false);
            if is_linux {
                let snap_name = args.snap.clone()
                    .or_else(|| sym_file.as_ref().and_then(fetch::snap::detect_snap_name));
                let arch = sym_file.as_ref()
                    .and_then(|sym| fetch::snap::snap_architecture(&sym.module.arch));
                if let (Some(snap_name), Some(arch)) = (snap_name, arch) {
                    let locator = fetch::snap::SnapLocator {
                        snap_name,
                        architecture: arch.to_string(),
                    };
                    let archive_client = fetch::build_archive_http_client(config)?;
                    let code_file = args.code_file.as_deref().unwrap_or(&args.debug_file);
                    match fetch::fetch_binary_snap(
                        &archive_client,
                        &cache,
                        code_file,
                        args.code_id.as_deref(),
                        &args.debug_id,
                        &locator,
                    )
                    .await
                    {
                        Ok(path) => Ok(path),
                        Err(snap_err) => {
                            warn!("Snap Store fallback failed: {snap_err}");
                            Err(e)
                        }
                    }
                } else {
                    Err(e)
                }
            } else {
                Err(e)
            }
        }
    };

    // If binary still not found, try FTP archive fallback (Linux + macOS)
    let bin_result = match bin_result {
        Ok(path) => Ok(path),
        Err(e) => {
            let os = sym_file.as_ref().map(|s| s.module.os.as_str()).unwrap_or("");
            let arch_str = sym_file.as_ref().map(|s| s.module.arch.as_str()).unwrap_or("");
            if let (Some(version), Some(channel)) = (&args.version, &args.channel) {
                if let Some(platform) = fetch::archive::ftp_platform(os, arch_str) {
                    let archive_client = fetch::build_archive_http_client(config)?;
                    let locator = fetch::archive::ArchiveLocator {
                        product: args.product.clone(),
                        version: version.clone(),
                        channel: channel.clone(),
                        platform: platform.to_string(),
                        build_id: args.build_id.clone(),
                    };
                    let code_file = args.code_file.as_deref().unwrap_or(&args.debug_file);
                    match fetch::fetch_binary_ftp(&archive_client, &cache, config, code_file, args.code_id.as_deref(), &args.debug_id, &locator).await {
                        Ok(path) => Ok(path),
                        Err(ftp_err) => {
                            warn!("FTP archive fallback failed: {ftp_err}");
                            Err(e)
                        }
                    }
                } else {
                    Err(e)
                }
            } else {
                Err(e)
            }
        }
    };

    // Determine target arch from sym file for fat binary selection
    let target_arch = sym_file.as_ref()
        .and_then(|sym| CpuArch::from_sym_arch(&sym.module.arch));

    // Parse binary if available — try PE first, then ELF, then Mach-O
    let mut binary_file: Option<Box<dyn BinaryFile>> = match &bin_result {
        Ok(path) => load_binary(path, target_arch),
        Err(e) => {
            warn!("binary not available: {e}");
            None
        }
    };

    // Determine architecture
    let arch = determine_arch(&sym_file, binary_file.as_ref().map(|b| b.as_ref()))?;

    // Find the target function
    let (func_name, func_addr, func_size) = find_target(args, &sym_file, binary_file.as_ref().map(|b| b.as_ref()))?;

    // Handle empty functions (size 0)
    if func_size == 0 {
        let msg = format!("function '{}' has size 0 at 0x{:x}", func_name, func_addr);
        match config.format {
            OutputFormat::Text => bail!("{msg}"),
            OutputFormat::Json => {
                let output = json::format_json_error(&msg);
                println!("{output}");
                return Ok(());
            }
        }
    }

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

    let demangle_enabled = !config.no_demangle;

    let function_info = FunctionInfo {
        name: maybe_demangle(&func_name, demangle_enabled),
        address: func_addr,
        size: func_size,
        source_file,
    };

    // Verify binary identity — discard the binary on mismatch to avoid
    // showing disassembly from a different build.
    if let Some(ref bin) = binary_file {
        if let Some(msg) = check_binary_identity(
            bin.as_ref(),
            args.code_id.as_deref(),
            &args.debug_id,
        ) {
            warn!("{msg}");
            binary_file = None;
        }
    }

    let warnings: Vec<String> = Vec::new();

    // Disassemble if binary is available
    if let Some(ref bin) = binary_file {
        let code = bin.extract_code(func_addr, func_size)
            .context("extracting code from binary")?;

        let disassembler = Disassembler::new(arch, config.syntax)?;
        let instructions = disassembler.disassemble(&code, func_addr, config.max_instructions)?;

        // Run annotation pipeline
        let mut annotated = annotate::annotate(
            instructions,
            sym_file.as_ref(),
            func_record,
            Some(bin.as_ref()),
            highlight_offset,
        );

        // Demangle call target names and inline frame names
        if demangle_enabled {
            for insn in &mut annotated {
                if let Some(ref name) = insn.call_target_name {
                    if !name.starts_with('[') {
                        insn.call_target_name = Some(maybe_demangle(name, true));
                    }
                }
                for frame in &mut insn.inline_frames {
                    frame.name = maybe_demangle(&frame.name, true);
                }
            }
        }

        let data_source = if sym_file.is_some() {
            DataSource::BinaryAndSym
        } else {
            DataSource::BinaryOnly
        };

        match config.format {
            OutputFormat::Text => {
                let output = text::format_text(&module_info, &function_info, &annotated, &data_source, &warnings);
                print!("{output}");
            }
            OutputFormat::Json => {
                let output = json::format_json(&module_info, &function_info, &annotated, &data_source, &warnings);
                println!("{output}");
            }
        }
    } else if let Some(ref sym) = sym_file {
        // Sym only - no binary available
        let sym_data = func_record.map(|func| build_sym_only_data(sym, func, demangle_enabled));
        match config.format {
            OutputFormat::Text => {
                let output = text::format_sym_only(&module_info, &function_info, sym_data.as_ref(), &warnings);
                print!("{output}");
            }
            OutputFormat::Json => {
                let output = json::format_json_sym_only(&module_info, &function_info, sym_data.as_ref(), &warnings);
                println!("{output}");
            }
        }
    } else {
        match config.format {
            OutputFormat::Text => {
                bail!(
                    "neither symbol file nor binary available for {}/{}",
                    args.debug_file,
                    args.debug_id
                );
            }
            OutputFormat::Json => {
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

/// Heuristic: debug file name looks like a Linux ELF shared library.
/// Used to try debuginfod when the sym file is unavailable.
fn looks_like_elf(debug_file: &str) -> bool {
    debug_file.contains(".so")
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

/// Load a binary file, trying PE first, then ELF, then Mach-O.
fn load_binary(path: &std::path::Path, target_arch: Option<CpuArch>) -> Option<Box<dyn BinaryFile>> {
    if let Ok(pe) = PeFile::load(path) {
        return Some(Box::new(pe));
    }
    if let Ok(elf) = ElfFile::load(path) {
        return Some(Box::new(elf));
    }
    if let Ok(macho) = MachOFile::load(path, target_arch) {
        return Some(Box::new(macho));
    }
    warn!("failed to parse binary: {}", path.display());
    None
}

/// Determine the CPU architecture from available sources.
fn determine_arch(
    sym_file: &Option<SymFile>,
    binary: Option<&dyn BinaryFile>,
) -> Result<CpuArch> {
    // Try sym file first
    if let Some(sym) = sym_file {
        if let Some(arch) = CpuArch::from_sym_arch(&sym.module.arch) {
            return Ok(arch);
        }
    }

    // Try binary file
    if let Some(bin) = binary {
        return Ok(bin.arch());
    }

    bail!("cannot determine architecture: no sym file or binary available")
}

/// Find the target function by name or offset.
fn find_target(
    args: &DisasmArgs,
    sym_file: &Option<SymFile>,
    binary: Option<&dyn BinaryFile>,
) -> Result<(String, u64, u64)> {
    if let Some(ref name) = args.function {
        find_by_name(name, args.fuzzy, sym_file, binary)
    } else if let Some(ref offset_str) = args.offset {
        let offset = parse_offset(offset_str)?;
        find_by_offset(offset, sym_file, binary)
    } else {
        bail!("either --function or --offset must be specified")
    }
}

fn find_by_name(
    name: &str,
    fuzzy: bool,
    sym_file: &Option<SymFile>,
    binary: Option<&dyn BinaryFile>,
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

    // Try binary exports — match against both mangled and demangled names
    if let Some(bin) = binary {
        let mut export_matches: Vec<(u64, &str)> = Vec::new();
        for &(rva, ref exp_name) in bin.exports() {
            let demangled = crate::demangle::demangle(exp_name);
            let matches = if fuzzy {
                exp_name.contains(name) || demangled.contains(name)
            } else {
                exp_name == name || demangled == name
            };
            if matches {
                export_matches.push((rva, exp_name));
            }
        }
        match export_matches.len() {
            0 => {}
            1 => {
                let (rva, exp_name) = export_matches[0];
                let size = estimate_export_size(bin.exports(), rva);
                return Ok((exp_name.to_string(), rva, size));
            }
            _ if fuzzy => {
                let mut msg = format!("ambiguous function name '{name}'. Matches:\n");
                for (i, &(rva, exp_name)) in export_matches.iter().enumerate().take(20) {
                    let size = estimate_export_size(bin.exports(), rva);
                    msg.push_str(&format!(
                        "  {}. {} (RVA: 0x{:x}, size: 0x{:x})\n",
                        i + 1,
                        crate::demangle::demangle(exp_name),
                        rva,
                        size
                    ));
                }
                if export_matches.len() > 20 {
                    msg.push_str(&format!("  ... and {} more\n", export_matches.len() - 20));
                }
                bail!("{msg}");
            }
            _ => {
                // Multiple exact matches (unlikely) — return the first
                let (rva, exp_name) = export_matches[0];
                let size = estimate_export_size(bin.exports(), rva);
                return Ok((exp_name.to_string(), rva, size));
            }
        }
    }

    bail!("function '{name}' not found in symbol file or binary exports")
}

fn find_by_offset(
    offset: u64,
    sym_file: &Option<SymFile>,
    binary: Option<&dyn BinaryFile>,
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

    // Try binary exports
    if let Some(bin) = binary {
        let exports = bin.exports();
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

/// Build enriched sym-only data from a parsed .sym file and function record.
fn build_sym_only_data(
    sym: &SymFile,
    func: &crate::symbols::breakpad::FuncRecord,
    demangle: bool,
) -> SymOnlyData {
    use std::collections::BTreeSet;

    // Source lines
    let source_lines: Vec<SymOnlyLine> = func
        .lines
        .iter()
        .map(|lr| SymOnlyLine {
            address: lr.address,
            size: lr.size,
            file: sym.files.get(lr.file_index).cloned().unwrap_or_default(),
            line: lr.line,
        })
        .collect();

    // Inline frames — one entry per range per inline record
    let inline_frames: Vec<SymOnlyInline> = func
        .inlines
        .iter()
        .flat_map(|inl| {
            let name = sym
                .inline_origins
                .get(inl.origin_index)
                .cloned()
                .unwrap_or_default();
            let name = maybe_demangle(&name, demangle);
            let call_file = sym.files.get(inl.call_file_index).cloned();
            inl.ranges.iter().map(move |&(start, size)| SymOnlyInline {
                address: start,
                end_address: start + size,
                depth: inl.depth,
                name: name.clone(),
                call_file: call_file.clone(),
                call_line: inl.call_line,
            })
        })
        .collect();

    // Collect unique source files
    let mut file_set = BTreeSet::new();
    for sl in &source_lines {
        if !sl.file.is_empty() {
            file_set.insert(sl.file.clone());
        }
    }
    for inf in &inline_frames {
        if let Some(ref f) = inf.call_file {
            file_set.insert(f.clone());
        }
    }
    let source_files: Vec<String> = file_set.into_iter().collect();

    SymOnlyData {
        source_lines,
        inline_frames,
        source_files,
    }
}

/// Check whether the loaded binary's identity matches the expected ID.
///
/// Compares the binary's build ID (ELF) or UUID (Mach-O) against the
/// code_id (if available) or the debug_id (converted via GUID byte-swapping).
/// Returns a mismatch message on failure, or `None` if the identity matches
/// or cannot be determined (e.g. PE binaries without a build ID).
fn check_binary_identity(
    binary: &dyn BinaryFile,
    code_id: Option<&str>,
    debug_id: &str,
) -> Option<String> {
    let actual_id = binary.build_id()?;

    // If we have code_id, compare directly (most reliable)
    if let Some(code_id) = code_id {
        if actual_id.eq_ignore_ascii_case(code_id) {
            return None;
        }
        return Some(format!(
            "Binary identity mismatch: expected {}, got {} -- disassembly may be from a different build",
            code_id, actual_id
        ));
    }

    // Derive expected ID from debug_id (handles both ELF build ID and Mach-O UUID)
    if let Ok(expected) = crate::symbols::id_convert::debug_id_to_build_id(debug_id) {
        if actual_id.to_lowercase().starts_with(&expected) {
            return None;
        }
        return Some(format!(
            "Binary identity mismatch: expected {}, got {} -- disassembly may be from a different build",
            expected, actual_id
        ));
    }

    None
}
