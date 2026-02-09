// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::fmt::Write;
use std::io::BufReader;
use std::path::Path;

use anyhow::{Result, Context, bail};
use serde::Serialize;

use super::{Cli, FormatArg, LookupArgs};
use crate::cache::Cache;
use crate::demangle::maybe_demangle;
use crate::fetch;
use crate::symbols::breakpad::SymFile;

/// Parse a hex offset string (with or without 0x prefix) to u64.
fn parse_offset(s: &str) -> Result<u64> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u64::from_str_radix(s, 16).context("invalid hex offset")
}

pub async fn run(args: &LookupArgs, cli: &Cli) -> Result<()> {
    let cache = Cache::new(cli.cache_dir.as_ref().map(Path::new))?;
    let client = fetch::build_http_client()?;

    // Fetch only the .sym file (no binary needed for lookup)
    let sym_path = fetch::fetch_sym_file(&client, &cache, &args.debug_file, &args.debug_id)
        .await
        .context("fetching symbol file")?;

    let file = std::fs::File::open(&sym_path)
        .with_context(|| format!("opening sym file: {}", sym_path.display()))?;
    let reader = BufReader::new(file);
    let sym = SymFile::parse(reader).context("parsing symbol file")?;

    if let Some(ref offset_str) = args.offset {
        let offset = parse_offset(offset_str)?;
        lookup_by_offset(offset, &sym, cli)
    } else if let Some(ref name) = args.function {
        lookup_by_name(name, args.fuzzy, &sym, cli)
    } else {
        bail!("either --function or --offset must be specified")
    }
}

fn lookup_by_offset(
    offset: u64,
    sym: &SymFile,
    cli: &Cli,
) -> Result<()> {
    let mut info = sym.resolve_address(offset)
        .ok_or_else(|| anyhow::anyhow!("no symbol found at offset 0x{:x}", offset))?;

    // Get source location and inline frames if we have a FuncRecord
    let func = sym.find_function_at_address(offset);
    let source_loc = func.and_then(|f| sym.get_source_line(offset, f));
    let mut inlines = func
        .map(|f| sym.get_inline_at(offset, f))
        .unwrap_or_default();

    // Demangle names for output
    let demangle_enabled = !cli.no_demangle;
    info.name = maybe_demangle(&info.name, demangle_enabled);
    for frame in &mut inlines {
        frame.name = maybe_demangle(&frame.name, demangle_enabled);
    }

    match cli.format {
        FormatArg::Text => {
            let output = format_offset_text(offset, &info, source_loc.as_ref(), &inlines);
            print!("{output}");
        }
        FormatArg::Json => {
            let output = format_offset_json(offset, &info, source_loc.as_ref(), &inlines);
            println!("{output}");
        }
    }

    Ok(())
}

fn lookup_by_name(
    name: &str,
    fuzzy: bool,
    sym: &SymFile,
    cli: &Cli,
) -> Result<()> {
    let demangle_enabled = !cli.no_demangle;

    let func = if fuzzy {
        let matches = sym.find_function_by_name_fuzzy(name);
        match matches.len() {
            0 => bail!("function not found: '{name}'"),
            1 => matches[0],
            _ => {
                // Multiple matches — report them as an error
                match cli.format {
                    FormatArg::Text => {
                        let mut msg = format!("ambiguous function name '{name}'. Matches:\n");
                        for (i, f) in matches.iter().enumerate().take(20) {
                            writeln!(
                                msg,
                                "  {}. {} (RVA: 0x{:x}, size: 0x{:x})",
                                i + 1, maybe_demangle(&f.name, demangle_enabled), f.address, f.size
                            ).unwrap();
                        }
                        if matches.len() > 20 {
                            writeln!(msg, "  ... and {} more", matches.len() - 20).unwrap();
                        }
                        bail!("{msg}");
                    }
                    FormatArg::Json => {
                        let output = format_fuzzy_matches_json(name, &matches, demangle_enabled);
                        println!("{output}");
                        std::process::exit(1);
                    }
                }
            }
        }
    } else {
        match sym.find_function_by_name(name) {
            Some(f) => f,
            None => {
                // Try fuzzy for helpful suggestions
                let suggestions = sym.find_function_by_name_fuzzy(name);
                if !suggestions.is_empty() {
                    let mut msg = format!("function '{name}' not found. Similar names:\n");
                    for f in suggestions.iter().take(10) {
                        writeln!(msg, "  - {} (0x{:x})", maybe_demangle(&f.name, demangle_enabled), f.address).unwrap();
                    }
                    bail!("{msg}");
                }
                bail!("function '{name}' not found");
            }
        }
    };

    // Get the function's primary source file from first line record
    let source_file = func
        .lines
        .first()
        .and_then(|lr| sym.files.get(lr.file_index).cloned());

    let demangled_name = maybe_demangle(&func.name, demangle_enabled);

    match cli.format {
        FormatArg::Text => {
            let output = format_function_text_demangled(&demangled_name, func, source_file.as_deref());
            print!("{output}");
        }
        FormatArg::Json => {
            let output = format_function_json_demangled(&demangled_name, func, source_file.as_deref());
            println!("{output}");
        }
    }

    Ok(())
}

// --- Text formatting ---

fn format_offset_text(
    offset: u64,
    info: &crate::symbols::breakpad::SymbolInfo,
    source: Option<&crate::symbols::breakpad::SourceLocation>,
    inlines: &[crate::symbols::breakpad::InlineInfo],
) -> String {
    let mut out = String::new();

    writeln!(
        out,
        "0x{:08x} => {} + 0x{:x}",
        offset, info.name, info.offset_in_function
    ).unwrap();

    if let Some(loc) = source {
        writeln!(out, "  Source: {}:{}", loc.file, loc.line).unwrap();
    }

    if let Some(size) = info.size {
        writeln!(
            out,
            "  Function range: 0x{:08x} - 0x{:08x} (0x{:x} bytes)",
            info.address,
            info.address + size,
            size
        ).unwrap();
    } else {
        writeln!(out, "  Function address: 0x{:08x}", info.address).unwrap();
    }

    for frame in inlines {
        let location = match &frame.call_file {
            Some(f) => format!(" ({}:{})", f, frame.call_line),
            None => String::new(),
        };
        writeln!(out, "  Inline: {}{}", frame.name, location).unwrap();
    }

    out
}

fn format_function_text(
    func: &crate::symbols::breakpad::FuncRecord,
    source_file: Option<&str>,
) -> String {
    format_function_text_demangled(&func.name, func, source_file)
}

fn format_function_text_demangled(
    display_name: &str,
    func: &crate::symbols::breakpad::FuncRecord,
    source_file: Option<&str>,
) -> String {
    let mut out = String::new();

    writeln!(out, "{}", display_name).unwrap();
    writeln!(out, "  Address: 0x{:08x}", func.address).unwrap();
    writeln!(out, "  Size: 0x{:x} bytes", func.size).unwrap();
    if let Some(file) = source_file {
        writeln!(out, "  Source: {}", file).unwrap();
    }

    out
}

// --- JSON formatting ---

#[derive(Serialize)]
struct JsonLookupOffset {
    offset: String,
    function: String,
    function_offset: String,
    function_address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    function_size: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_line: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    inline_frames: Vec<JsonInlineFrame>,
}

#[derive(Serialize)]
struct JsonInlineFrame {
    function: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_file: Option<String>,
    source_line: u32,
}

#[derive(Serialize)]
struct JsonLookupFunction {
    function: String,
    function_address: String,
    function_size: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_file: Option<String>,
}

#[derive(Serialize)]
struct JsonFuzzyError {
    error: JsonErrorDetail,
    total_matches: usize,
    matches: Vec<JsonFuzzyMatch>,
}

#[derive(Serialize)]
struct JsonErrorDetail {
    code: String,
    message: String,
}

#[derive(Serialize)]
struct JsonFuzzyMatch {
    name: String,
    address: String,
    size: String,
}

fn format_offset_json(
    offset: u64,
    info: &crate::symbols::breakpad::SymbolInfo,
    source: Option<&crate::symbols::breakpad::SourceLocation>,
    inlines: &[crate::symbols::breakpad::InlineInfo],
) -> String {
    let output = JsonLookupOffset {
        offset: format!("0x{:x}", offset),
        function: info.name.clone(),
        function_offset: format!("0x{:x}", info.offset_in_function),
        function_address: format!("0x{:x}", info.address),
        function_size: info.size.map(|s| format!("0x{:x}", s)),
        source_file: source.map(|s| s.file.clone()),
        source_line: source.map(|s| s.line),
        inline_frames: inlines
            .iter()
            .map(|f| JsonInlineFrame {
                function: f.name.clone(),
                source_file: f.call_file.clone(),
                source_line: f.call_line,
            })
            .collect(),
    };
    serde_json::to_string_pretty(&output).expect("JSON serialization should not fail")
}

fn format_function_json(
    func: &crate::symbols::breakpad::FuncRecord,
    source_file: Option<&str>,
) -> String {
    format_function_json_demangled(&func.name, func, source_file)
}

fn format_function_json_demangled(
    display_name: &str,
    func: &crate::symbols::breakpad::FuncRecord,
    source_file: Option<&str>,
) -> String {
    let output = JsonLookupFunction {
        function: display_name.to_string(),
        function_address: format!("0x{:x}", func.address),
        function_size: format!("0x{:x}", func.size),
        source_file: source_file.map(|s| s.to_string()),
    };
    serde_json::to_string_pretty(&output).expect("JSON serialization should not fail")
}

fn format_fuzzy_matches_json(
    name: &str,
    matches: &[&crate::symbols::breakpad::FuncRecord],
    demangle_enabled: bool,
) -> String {
    let output = JsonFuzzyError {
        error: JsonErrorDetail {
            code: "AMBIGUOUS_FUNCTION".to_string(),
            message: format!("ambiguous function name '{name}'"),
        },
        total_matches: matches.len(),
        matches: matches
            .iter()
            .take(20)
            .map(|f| JsonFuzzyMatch {
                name: maybe_demangle(&f.name, demangle_enabled),
                address: format!("0x{:x}", f.address),
                size: format!("0x{:x}", f.size),
            })
            .collect(),
    };
    serde_json::to_string_pretty(&output).expect("JSON serialization should not fail")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbols::breakpad::{SymFile, SymbolInfo, SourceLocation, InlineInfo};
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
    fn test_offset_text_with_func() {
        let info = SymbolInfo {
            name: "TestFunction".to_string(),
            address: 0x1000,
            size: Some(0x80),
            offset_in_function: 0x20,
        };
        let source = SourceLocation {
            file: "src/main.cpp".to_string(),
            line: 11,
        };
        let output = format_offset_text(0x1020, &info, Some(&source), &[]);
        assert!(output.contains("0x00001020 => TestFunction + 0x20"));
        assert!(output.contains("Source: src/main.cpp:11"));
        assert!(output.contains("Function range: 0x00001000 - 0x00001080 (0x80 bytes)"));
    }

    #[test]
    fn test_offset_text_with_public() {
        let info = SymbolInfo {
            name: "_PublicSymbol".to_string(),
            address: 0x3000,
            size: None,
            offset_in_function: 0x10,
        };
        let output = format_offset_text(0x3010, &info, None, &[]);
        assert!(output.contains("0x00003010 => _PublicSymbol + 0x10"));
        assert!(output.contains("Function address: 0x00003000"));
        assert!(!output.contains("Source:"));
    }

    #[test]
    fn test_offset_text_with_inlines() {
        let info = SymbolInfo {
            name: "TestFunction".to_string(),
            address: 0x1000,
            size: Some(0x80),
            offset_in_function: 0x25,
        };
        let inlines = vec![InlineInfo {
            name: "InlinedHelper".to_string(),
            depth: 0,
            call_file: Some("src/main.cpp".to_string()),
            call_line: 10,
        }];
        let output = format_offset_text(0x1025, &info, None, &inlines);
        assert!(output.contains("Inline: InlinedHelper (src/main.cpp:10)"));
    }

    #[test]
    fn test_function_text() {
        let sym = SymFile::parse(Cursor::new(make_test_sym())).unwrap();
        let func = sym.find_function_by_name("TestFunction").unwrap();
        let output = format_function_text(func, Some("src/main.cpp"));
        assert!(output.contains("TestFunction"));
        assert!(output.contains("Address: 0x00001000"));
        assert!(output.contains("Size: 0x80 bytes"));
        assert!(output.contains("Source: src/main.cpp"));
    }

    #[test]
    fn test_offset_json() {
        let info = SymbolInfo {
            name: "TestFunction".to_string(),
            address: 0x1000,
            size: Some(0x80),
            offset_in_function: 0x20,
        };
        let source = SourceLocation {
            file: "src/main.cpp".to_string(),
            line: 11,
        };
        let inlines = vec![InlineInfo {
            name: "InlinedHelper".to_string(),
            depth: 0,
            call_file: Some("src/main.cpp".to_string()),
            call_line: 10,
        }];
        let json_str = format_offset_json(0x1020, &info, Some(&source), &inlines);
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(v["offset"], "0x1020");
        assert_eq!(v["function"], "TestFunction");
        assert_eq!(v["function_offset"], "0x20");
        assert_eq!(v["function_address"], "0x1000");
        assert_eq!(v["function_size"], "0x80");
        assert_eq!(v["source_file"], "src/main.cpp");
        assert_eq!(v["source_line"], 11);

        let frames = v["inline_frames"].as_array().unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0]["function"], "InlinedHelper");
        assert_eq!(frames[0]["source_file"], "src/main.cpp");
        assert_eq!(frames[0]["source_line"], 10);
    }

    #[test]
    fn test_function_json() {
        let sym = SymFile::parse(Cursor::new(make_test_sym())).unwrap();
        let func = sym.find_function_by_name("TestFunction").unwrap();
        let json_str = format_function_json(func, Some("src/main.cpp"));
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(v["function"], "TestFunction");
        assert_eq!(v["function_address"], "0x1000");
        assert_eq!(v["function_size"], "0x80");
        assert_eq!(v["source_file"], "src/main.cpp");
    }

    #[test]
    fn test_fuzzy_matches_json() {
        let sym = SymFile::parse(Cursor::new(make_test_sym())).unwrap();
        let matches = sym.find_function_by_name_fuzzy("Function");
        let json_str = format_fuzzy_matches_json("Function", &matches, false);
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(v["error"]["code"], "AMBIGUOUS_FUNCTION");
        assert_eq!(v["total_matches"], 2);
        let matches = v["matches"].as_array().unwrap();
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_offset_json_no_source() {
        let info = SymbolInfo {
            name: "_PublicSymbol".to_string(),
            address: 0x3000,
            size: None,
            offset_in_function: 0x10,
        };
        let json_str = format_offset_json(0x3010, &info, None, &[]);
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(v["function"], "_PublicSymbol");
        assert!(v["function_size"].is_null());
        assert!(v["source_file"].is_null());
        assert!(v["source_line"].is_null());
    }
}
