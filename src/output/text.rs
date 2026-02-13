// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::fmt::Write;

use crate::disasm::annotate::AnnotatedInstruction;

/// Information about the module being disassembled.
pub struct ModuleInfo {
    pub debug_file: String,
    pub debug_id: String,
    pub code_file: Option<String>,
    pub arch: String,
}

/// Information about the function being disassembled.
pub struct FunctionInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub source_file: Option<String>,
}

/// Data source indicator.
pub enum DataSource {
    BinaryAndSym,
    BinaryAndPdb,
    BinaryOnly,
    SymOnly,
    PdbOnly,
}

impl std::fmt::Display for DataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataSource::BinaryAndSym => write!(f, "binary+sym"),
            DataSource::BinaryAndPdb => write!(f, "binary+pdb"),
            DataSource::BinaryOnly => write!(f, "binary"),
            DataSource::SymOnly => write!(f, "sym"),
            DataSource::PdbOnly => write!(f, "pdb"),
        }
    }
}

/// Format disassembly output as text.
pub fn format_text(
    module: &ModuleInfo,
    function: &FunctionInfo,
    instructions: &[AnnotatedInstruction],
    data_source: &DataSource,
    warnings: &[String],
) -> String {
    let mut out = String::new();

    // Header
    let code_file_display = module.code_file.as_deref().unwrap_or(&module.debug_file);
    writeln!(
        out,
        "; Module: {} ({} / {})",
        code_file_display, module.debug_file, module.debug_id
    )
    .unwrap();
    writeln!(
        out,
        "; Function: {} (RVA: 0x{:x}, size: 0x{:x})",
        function.name, function.address, function.size
    )
    .unwrap();
    if let Some(ref source_file) = function.source_file {
        writeln!(out, "; Source: {}", source_file).unwrap();
    }
    writeln!(out, "; Architecture: {}", module.arch).unwrap();
    writeln!(out, "; Data sources: {}", data_source).unwrap();

    for w in warnings {
        writeln!(out, "; WARNING: {}", w).unwrap();
    }

    if matches!(data_source, DataSource::SymOnly | DataSource::PdbOnly) {
        writeln!(out, ";").unwrap();
        writeln!(
            out,
            "; Binary not available -- no disassembly. Function metadata only."
        )
        .unwrap();
        return out;
    }

    writeln!(out, ";").unwrap();

    // Track state for transition detection
    let mut prev_source: Option<(String, u32)> = None;
    let mut prev_inline_names: Vec<String> = Vec::new();

    for insn in instructions {
        let curr_inline_names: Vec<String> =
            insn.inline_frames.iter().map(|f| f.name.clone()).collect();

        // Find common prefix between previous and current inline stacks
        let common = prev_inline_names
            .iter()
            .zip(curr_inline_names.iter())
            .take_while(|(a, b)| a == b)
            .count();

        // Close frames that are no longer active (deepest first)
        for i in (common..prev_inline_names.len()).rev() {
            writeln!(out, "    ; [end inline] {}", prev_inline_names[i]).unwrap();
        }

        // Open new inline frames
        for frame in insn.inline_frames.iter().skip(common) {
            let location = match &frame.call_file {
                Some(f) => format!(" ({}:{})", f, frame.call_line),
                None => String::new(),
            };
            writeln!(out, "    ; [inline] {}{}", frame.name, location).unwrap();
        }

        prev_inline_names = curr_inline_names;

        // Emit source line annotation when file:line changes
        if let (Some(ref file), Some(line)) = (&insn.source_file, insn.source_line) {
            let curr = (file.clone(), line);
            if prev_source.as_ref() != Some(&curr) {
                writeln!(out, "    ; {}:{}", file, line).unwrap();
                prev_source = Some(curr);
            }
        }

        // Emit the instruction
        let marker = if insn.highlighted { "==> " } else { "    " };
        let main_part = format!(
            "0x{:08x}:  {:<8}{}",
            insn.instruction.address, insn.instruction.mnemonic, insn.instruction.operands
        );

        write!(out, "{}{}", marker, main_part).unwrap();

        // Call target annotation
        if let Some(ref target_name) = insn.call_target_name {
            let padding = 44usize.saturating_sub(main_part.len()).max(2);
            write!(out, "{:width$}; {}", "", target_name, width = padding).unwrap();
        }

        writeln!(out).unwrap();
    }

    // Close any remaining inline frames at the end
    for i in (0..prev_inline_names.len()).rev() {
        writeln!(out, "    ; [end inline] {}", prev_inline_names[i]).unwrap();
    }

    out
}

/// Enriched data available when only the .sym file is present.
pub struct SymOnlyData {
    pub source_lines: Vec<SymOnlyLine>,
    pub inline_frames: Vec<SymOnlyInline>,
    pub source_files: Vec<String>,
}

pub struct SymOnlyLine {
    pub address: u64,
    pub size: u64,
    pub file: String,
    pub line: u32,
}

pub struct SymOnlyInline {
    pub address: u64,
    pub end_address: u64,
    pub depth: u32,
    pub name: String,
    pub call_file: Option<String>,
    pub call_line: u32,
}

/// Format a "sym only" result (no binary available).
///
/// When `sym_data` is `Some`, renders source line mapping, inline frames, and
/// source file list extracted from the .sym file. When `None`, shows only the
/// minimal "Function metadata only." message.
pub fn format_sym_only(
    module: &ModuleInfo,
    function: &FunctionInfo,
    sym_data: Option<&SymOnlyData>,
    data_source: &DataSource,
    warnings: &[String],
) -> String {
    let mut out = String::new();

    // Header (same as format_text)
    let code_file_display = module.code_file.as_deref().unwrap_or(&module.debug_file);
    writeln!(
        out,
        "; Module: {} ({} / {})",
        code_file_display, module.debug_file, module.debug_id
    )
    .unwrap();
    writeln!(
        out,
        "; Function: {} (RVA: 0x{:x}, size: 0x{:x})",
        function.name, function.address, function.size
    )
    .unwrap();
    if let Some(ref source_file) = function.source_file {
        writeln!(out, "; Source: {}", source_file).unwrap();
    }
    writeln!(out, "; Architecture: {}", module.arch).unwrap();
    writeln!(out, "; Data sources: {}", data_source).unwrap();

    for w in warnings {
        writeln!(out, "; WARNING: {}", w).unwrap();
    }

    if let Some(data) = sym_data {
        // Source line mapping
        if !data.source_lines.is_empty() {
            writeln!(out, ";").unwrap();
            writeln!(out, "; Source line mapping:").unwrap();
            for sl in &data.source_lines {
                writeln!(
                    out,
                    ";   0x{:08x} - 0x{:08x}  {}:{}",
                    sl.address,
                    sl.address + sl.size,
                    sl.file,
                    sl.line
                )
                .unwrap();
            }
        }

        // Inline frames
        if !data.inline_frames.is_empty() {
            writeln!(out, ";").unwrap();
            writeln!(out, "; Inline frames:").unwrap();
            for inf in &data.inline_frames {
                let location = match &inf.call_file {
                    Some(f) => format!(" ({}:{})", f, inf.call_line),
                    None => String::new(),
                };
                writeln!(
                    out,
                    ";   0x{:08x} - 0x{:08x}  [depth {}] {}{}",
                    inf.address, inf.end_address, inf.depth, inf.name, location
                )
                .unwrap();
            }
        }

        // Source files
        if !data.source_files.is_empty() {
            writeln!(out, ";").unwrap();
            writeln!(out, "; Source files:").unwrap();
            for sf in &data.source_files {
                writeln!(out, ";   {}", sf).unwrap();
            }
        }
    }

    writeln!(out, ";").unwrap();
    writeln!(
        out,
        "; Binary not available -- no disassembly.{}",
        if sym_data.is_none() { " Function metadata only." } else { "" }
    )
    .unwrap();

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_module_info() -> ModuleInfo {
        ModuleInfo {
            debug_file: "test.pdb".to_string(),
            debug_id: "AABBCCDD11223344".to_string(),
            code_file: Some("test.dll".to_string()),
            arch: "x86_64".to_string(),
        }
    }

    fn make_function_info() -> FunctionInfo {
        FunctionInfo {
            name: "TestFunction".to_string(),
            address: 0x1a3e80,
            size: 0x120,
            source_file: Some("src/main.cpp".to_string()),
        }
    }

    #[test]
    fn test_data_source_display() {
        assert_eq!(DataSource::BinaryAndSym.to_string(), "binary+sym");
        assert_eq!(DataSource::BinaryAndPdb.to_string(), "binary+pdb");
        assert_eq!(DataSource::BinaryOnly.to_string(), "binary");
        assert_eq!(DataSource::SymOnly.to_string(), "sym");
        assert_eq!(DataSource::PdbOnly.to_string(), "pdb");
    }

    #[test]
    fn test_sym_only_none_minimal() {
        let module = make_module_info();
        let function = make_function_info();
        let output = format_sym_only(&module, &function, None, &DataSource::SymOnly, &[]);

        assert!(output.contains("; Data sources: sym"));
        assert!(output.contains("Function metadata only."));
        assert!(!output.contains("Source line mapping:"));
        assert!(!output.contains("Inline frames:"));
        assert!(!output.contains("Source files:"));
    }

    #[test]
    fn test_sym_only_enriched() {
        let module = make_module_info();
        let function = make_function_info();

        let sym_data = SymOnlyData {
            source_lines: vec![
                SymOnlyLine {
                    address: 0x1a3e80,
                    size: 0x10,
                    file: "src/main.cpp".to_string(),
                    line: 10,
                },
                SymOnlyLine {
                    address: 0x1a3e90,
                    size: 0x30,
                    file: "src/main.cpp".to_string(),
                    line: 11,
                },
            ],
            inline_frames: vec![SymOnlyInline {
                address: 0x1a3e90,
                end_address: 0x1a3ec0,
                depth: 0,
                name: "InlinedHelper".to_string(),
                call_file: Some("src/helper.h".to_string()),
                call_line: 40,
            }],
            source_files: vec![
                "src/helper.h".to_string(),
                "src/main.cpp".to_string(),
            ],
        };

        let output = format_sym_only(&module, &function, Some(&sym_data), &DataSource::SymOnly, &[]);

        assert!(output.contains("; Source line mapping:"));
        assert!(output.contains("0x001a3e80 - 0x001a3e90  src/main.cpp:10"));
        assert!(output.contains("0x001a3e90 - 0x001a3ec0  src/main.cpp:11"));
        assert!(output.contains("; Inline frames:"));
        assert!(output.contains("[depth 0] InlinedHelper (src/helper.h:40)"));
        assert!(output.contains("; Source files:"));
        assert!(output.contains(";   src/main.cpp"));
        assert!(output.contains(";   src/helper.h"));
        assert!(output.contains("; Binary not available -- no disassembly."));
        assert!(!output.contains("Function metadata only."));
    }
}
