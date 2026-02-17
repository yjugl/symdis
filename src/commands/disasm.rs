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
use crate::symbols::pdb as pdb_parser;

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

    let is_pdb_module = args.debug_file.to_ascii_lowercase().ends_with(".pdb");

    // Fetch symbol data and binary concurrently.
    // When --pdb is set and debug_file is a .pdb, prefer PDB over .sym.
    let use_pdb_primary = args.pdb && is_pdb_module;

    let sym_fut = async {
        if use_pdb_primary {
            // Skip .sym when --pdb is explicitly requested; we'll fetch PDB instead
            Err(anyhow::anyhow!("skipped: --pdb flag set"))
        } else {
            fetch::fetch_sym_file(&client, &cache, config, &args.debug_file, &args.debug_id).await
        }
    };
    let pdb_fut = async {
        if use_pdb_primary {
            fetch::fetch_pdb_file(&client, &cache, config, &args.debug_file, &args.debug_id).await
        } else {
            Err(anyhow::anyhow!("skipped: --pdb not set"))
        }
    };
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

    let (sym_result, pdb_result, bin_result) = tokio::join!(sym_fut, pdb_fut, bin_fut);

    // Track whether symbol data came from PDB (affects DataSource display)
    let mut from_pdb = false;

    // Parse symbol data: .sym file or PDB
    let sym_file = if use_pdb_primary {
        // --pdb mode: try PDB first, fall back to .sym
        match &pdb_result {
            Ok(path) => {
                match pdb_parser::parse_pdb(path, &args.debug_file, &args.debug_id) {
                    Ok(sym) => {
                        from_pdb = true;
                        Some(sym)
                    }
                    Err(e) => {
                        warn!("failed to parse PDB file: {e}");
                        None
                    }
                }
            }
            Err(e) => {
                warn!("PDB file not available: {e}");
                // Fall back to .sym
                match fetch::fetch_sym_file(&client, &cache, config, &args.debug_file, &args.debug_id).await {
                    Ok(path) => parse_sym_file(&path),
                    Err(e2) => {
                        warn!("sym file also not available: {e2}");
                        None
                    }
                }
            }
        }
    } else {
        // Default mode: try .sym, auto-fallback to PDB if .sym unavailable
        match &sym_result {
            Ok(path) => parse_sym_file(path),
            Err(e) => {
                warn!("sym file not available: {e}");
                // Auto-fallback: try PDB if this is a Windows module
                if is_pdb_module {
                    match fetch::fetch_pdb_file(&client, &cache, config, &args.debug_file, &args.debug_id).await {
                        Ok(path) => {
                            match pdb_parser::parse_pdb(&path, &args.debug_file, &args.debug_id) {
                                Ok(sym) => {
                                    from_pdb = true;
                                    Some(sym)
                                }
                                Err(e2) => {
                                    warn!("failed to parse PDB file: {e2}");
                                    None
                                }
                            }
                        }
                        Err(e2) => {
                            warn!("PDB fallback also not available: {e2}");
                            None
                        }
                    }
                } else {
                    None
                }
            }
        }
    };

    // If binary fetch failed and sym file indicates Linux, try debuginfod
    let bin_result = match bin_result {
        Ok(path) => Ok(path),
        Err(e) => {
            let is_linux = sym_file.as_ref()
                .map(|sym| sym.module.os.eq_ignore_ascii_case("linux"))
                .unwrap_or_else(|| looks_like_elf(&args.debug_file, args.code_id.as_deref()));
            if is_linux {
                let code_file = args.code_file.as_deref().unwrap_or(&args.debug_file);
                match fetch::fetch_binary_debuginfod(&client, &cache, config, code_file, args.code_id.as_deref(), &args.debug_id).await {
                    Ok(path) => Ok(path),
                    Err(_) => {
                        let msg = e.to_string();
                        if msg.contains("\nTried: ") {
                            Err(anyhow::anyhow!("{msg}, debuginfod"))
                        } else {
                            Err(e)
                        }
                    }
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
                .unwrap_or_else(|| looks_like_elf(&args.debug_file, args.code_id.as_deref()));
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
                            warn!("Snap Store fallback failed: {snap_err:#}");
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
            let (os, arch_str) = sym_file.as_ref()
                .map(|s| (s.module.os.as_str(), s.module.arch.as_str()))
                .unwrap_or_else(|| infer_platform_from_code_id(args.code_id.as_deref()));
            if let (Some(version), Some(channel)) = (&args.version, &args.channel) {
                match fetch::archive::resolve_product_platform(&args.product, os, arch_str) {
                    Ok(Some((product, platform))) => {
                        let archive_client = fetch::build_archive_http_client(config)?;
                        let locator = fetch::archive::ArchiveLocator {
                            product,
                            version: version.clone(),
                            channel: channel.clone(),
                            platform,
                            build_id: args.build_id.clone(),
                        };
                        let code_file = args.code_file.as_deref().unwrap_or(&args.debug_file);
                        match fetch::fetch_binary_ftp(&archive_client, &cache, config, code_file, args.code_id.as_deref(), &args.debug_id, &locator).await {
                            Ok(path) => Ok(path),
                            Err(ftp_err) => {
                                warn!("FTP archive fallback failed: {ftp_err:#}");
                                Err(e)
                            }
                        }
                    }
                    Ok(None) => Err(e),
                    Err(product_err) => {
                        warn!("product/platform resolution failed: {product_err:#}");
                        Err(e)
                    }
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

    let mut warnings: Vec<String> = Vec::new();

    // Disassemble if binary is available
    if let Some(ref bin) = binary_file {
        let code = bin.extract_code(func_addr, func_size)
            .context("extracting code from binary")?;

        let disassembler = Disassembler::new(arch, config.syntax)?;
        let image_base = bin.image_base();
        let (instructions, total_count) = disassembler.disassemble(
            &code, func_addr, config.max_instructions, highlight_offset, image_base,
        )?;

        if instructions.len() < total_count {
            warnings.push(format!(
                "Output truncated to {} of {} instructions. \
                 Use --max-instructions {} to see all.",
                instructions.len(), total_count, total_count
            ));
        }

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
            if from_pdb { DataSource::BinaryAndPdb } else { DataSource::BinaryAndSym }
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
        let data_source = if from_pdb { DataSource::PdbOnly } else { DataSource::SymOnly };
        match config.format {
            OutputFormat::Text => {
                let output = text::format_sym_only(&module_info, &function_info, sym_data.as_ref(), &data_source, &warnings);
                print!("{output}");
            }
            OutputFormat::Json => {
                let output = json::format_json_sym_only(&module_info, &function_info, sym_data.as_ref(), &data_source, &warnings);
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

/// Parse a .sym file from a path, returning None on failure.
fn parse_sym_file(path: &std::path::Path) -> Option<SymFile> {
    let file = std::fs::File::open(path)
        .map_err(|e| warn!("opening sym file: {e}"))
        .ok()?;
    let reader = BufReader::new(file);
    match SymFile::parse(reader) {
        Ok(sym) => Some(sym),
        Err(e) => {
            warn!("failed to parse sym file: {e}");
            None
        }
    }
}

/// Infer OS and architecture from code_id format when sym file is unavailable.
/// 40-char hex = ELF (Linux, guess x86_64). 32-char hex = Mach-O (macOS).
fn infer_platform_from_code_id(code_id: Option<&str>) -> (&'static str, &'static str) {
    match code_id {
        Some(id) if id.len() == 40 && id.bytes().all(|b| b.is_ascii_hexdigit()) => {
            ("Linux", "x86_64")
        }
        Some(id) if id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()) => {
            ("mac", "")
        }
        _ => ("", ""),
    }
}

/// Heuristic: module looks like a Linux ELF binary.
/// Checks for `.so` in the debug file name or a 40-char hex code ID (GNU build ID).
fn looks_like_elf(debug_file: &str, code_id: Option<&str>) -> bool {
    debug_file.contains(".so")
        || code_id.is_some_and(|id| {
            id.len() == 40 && id.bytes().all(|b| b.is_ascii_hexdigit())
        })
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
        // 1. Try FUNC records
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

        // Exact FUNC match
        if let Some(func) = sym.find_function_by_name(name) {
            return Ok((func.name.clone(), func.address, func.size));
        }

        // 2. Try PUBLIC symbols (exact, then fuzzy with demangling)
        if let Some(result) = find_public_by_name(name, fuzzy, sym, binary)? {
            return Ok(result);
        }

        // If not exact match and not fuzzy, try fuzzy for a helpful error
        let func_suggestions = sym.find_function_by_name_fuzzy(name);
        let public_suggestions = sym.find_public_by_name_fuzzy(name);
        if !func_suggestions.is_empty() || !public_suggestions.is_empty() {
            let mut msg = format!("function '{name}' not found. Similar names:\n");
            for f in func_suggestions.iter().take(5) {
                msg.push_str(&format!("  - {} (FUNC, 0x{:x})\n", f.name, f.address));
            }
            for p in public_suggestions.iter().take(5) {
                msg.push_str(&format!("  - {} (PUBLIC, 0x{:x})\n", p.name, p.address));
            }
            bail!("{msg}");
        }
    }

    // 3. Try binary exports — match against both mangled and demangled names
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

    bail!("function '{name}' not found in symbol file, PUBLIC symbols, or binary exports")
}

/// Search PUBLIC symbols by name. Tries exact match first, then demangled match,
/// then fuzzy (substring) match if `fuzzy` is true.
fn find_public_by_name(
    name: &str,
    fuzzy: bool,
    sym: &SymFile,
    binary: Option<&dyn BinaryFile>,
) -> Result<Option<(String, u64, u64)>> {
    // Exact match on raw name
    if let Some(public) = sym.find_public_by_name(name) {
        let size = resolve_public_size(&sym.publics, public.address, binary);
        return Ok(Some((public.name.clone(), public.address, size)));
    }

    // Exact match on demangled name
    for public in &sym.publics {
        let demangled = crate::demangle::demangle(&public.name);
        if demangled == name {
            let size = resolve_public_size(&sym.publics, public.address, binary);
            return Ok(Some((public.name.clone(), public.address, size)));
        }
    }

    if fuzzy {
        // Fuzzy match on raw and demangled names
        let mut matches: Vec<&crate::symbols::breakpad::PublicRecord> = Vec::new();
        for public in &sym.publics {
            let demangled = crate::demangle::demangle(&public.name);
            if public.name.contains(name) || demangled.contains(name) {
                matches.push(public);
            }
        }
        match matches.len() {
            0 => {}
            1 => {
                let public = matches[0];
                let size = resolve_public_size(&sym.publics, public.address, binary);
                return Ok(Some((public.name.clone(), public.address, size)));
            }
            _ => {
                let mut msg = format!("ambiguous PUBLIC symbol name '{name}'. Matches:\n");
                for (i, p) in matches.iter().enumerate().take(20) {
                    let size = resolve_public_size(&sym.publics, p.address, binary);
                    msg.push_str(&format!(
                        "  {}. {} (RVA: 0x{:x}, size: 0x{:x})\n",
                        i + 1,
                        crate::demangle::demangle(&p.name),
                        p.address,
                        size
                    ));
                }
                if matches.len() > 20 {
                    msg.push_str(&format!("  ... and {} more\n", matches.len() - 20));
                }
                bail!("{msg}");
            }
        }
    }

    Ok(None)
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
            let size = resolve_public_size(&sym.publics, public.address, binary);
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

/// Resolve the size of a PUBLIC symbol, preferring exact .pdata bounds from the
/// binary when available, falling back to distance-to-next-symbol estimation.
fn resolve_public_size(
    publics: &[crate::symbols::breakpad::PublicRecord],
    addr: u64,
    binary: Option<&dyn BinaryFile>,
) -> u64 {
    // Prefer exact bounds from PE .pdata section
    if let Some(bin) = binary {
        if let Some((begin, end)) = bin.function_bounds(addr) {
            return end - begin;
        }
    }
    // Fall back to estimation from next PUBLIC symbol
    estimate_public_size(publics, addr)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbols::breakpad::PublicRecord;

    /// Stub binary that implements function_bounds() with preset pdata entries.
    struct StubBinary {
        pdata: Vec<(u64, u64)>,
    }

    impl BinaryFile for StubBinary {
        fn arch(&self) -> CpuArch { CpuArch::X86_64 }
        fn extract_code(&self, _rva: u64, _size: u64) -> Result<Vec<u8>> { Ok(Vec::new()) }
        fn resolve_import(&self, _rva: u64) -> Option<(String, String)> { None }
        fn exports(&self) -> &[(u64, String)] { &[] }
        fn function_bounds(&self, rva: u64) -> Option<(u64, u64)> {
            let idx = self.pdata.partition_point(|&(begin, _)| begin <= rva);
            if idx == 0 { return None; }
            let (begin, end) = self.pdata[idx - 1];
            if rva < end { Some((begin, end)) } else { None }
        }
    }

    fn make_publics() -> Vec<PublicRecord> {
        vec![
            PublicRecord { address: 0x1000, param_size: 0, name: "FuncA".to_string() },
            PublicRecord { address: 0x1200, param_size: 0, name: "FuncB".to_string() },
            PublicRecord { address: 0x1500, param_size: 0, name: "FuncC".to_string() },
        ]
    }

    #[test]
    fn test_resolve_public_size_with_pdata() {
        let publics = make_publics();
        let binary = StubBinary {
            pdata: vec![(0x1000, 0x1180), (0x1200, 0x1400), (0x1500, 0x1600)],
        };
        // .pdata gives exact size
        assert_eq!(resolve_public_size(&publics, 0x1000, Some(&binary)), 0x180);
        assert_eq!(resolve_public_size(&publics, 0x1200, Some(&binary)), 0x200);
        assert_eq!(resolve_public_size(&publics, 0x1500, Some(&binary)), 0x100);
    }

    #[test]
    fn test_resolve_public_size_without_binary() {
        let publics = make_publics();
        // No binary — falls back to estimate from next PUBLIC
        assert_eq!(resolve_public_size(&publics, 0x1000, None), 0x200); // 0x1200 - 0x1000
        assert_eq!(resolve_public_size(&publics, 0x1200, None), 0x300); // 0x1500 - 0x1200
        assert_eq!(resolve_public_size(&publics, 0x1500, None), 0x10000); // last, capped
    }

    #[test]
    fn test_resolve_public_size_no_pdata_match() {
        let publics = make_publics();
        // Binary has no .pdata for this address — falls back to estimate
        let binary = StubBinary { pdata: vec![(0x5000, 0x5100)] };
        assert_eq!(resolve_public_size(&publics, 0x1000, Some(&binary)), 0x200);
    }

    #[test]
    fn test_estimate_public_size() {
        let publics = make_publics();
        assert_eq!(estimate_public_size(&publics, 0x1000), 0x200);
        assert_eq!(estimate_public_size(&publics, 0x1200), 0x300);
        assert_eq!(estimate_public_size(&publics, 0x1500), 0x10000);
    }

    #[test]
    fn test_estimate_export_size() {
        let exports = vec![
            (0x1000u64, "A".to_string()),
            (0x1100, "B".to_string()),
            (0x1300, "C".to_string()),
        ];
        assert_eq!(estimate_export_size(&exports, 0x1000), 0x100);
        assert_eq!(estimate_export_size(&exports, 0x1100), 0x200);
        assert_eq!(estimate_export_size(&exports, 0x1300), 0x10000);
    }
}
