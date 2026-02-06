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
    BinaryOnly,
    SymOnly,
}

impl std::fmt::Display for DataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataSource::BinaryAndSym => write!(f, "binary+sym"),
            DataSource::BinaryOnly => write!(f, "binary"),
            DataSource::SymOnly => write!(f, "sym"),
        }
    }
}

/// Format disassembly output as text.
pub fn format_text(
    module: &ModuleInfo,
    function: &FunctionInfo,
    instructions: &[AnnotatedInstruction],
    data_source: &DataSource,
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

    if let DataSource::SymOnly = data_source {
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

/// Format a "sym only" result (no binary available).
pub fn format_sym_only(module: &ModuleInfo, function: &FunctionInfo) -> String {
    format_text(module, function, &[], &DataSource::SymOnly)
}
