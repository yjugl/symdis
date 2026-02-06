use std::fmt::Write;

use crate::disasm::engine::Instruction;

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
    instructions: &[Instruction],
    data_source: &DataSource,
    highlight_offset: Option<u64>,
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

    // Instructions
    for insn in instructions {
        let highlight = highlight_offset
            .is_some_and(|h| h == insn.address);

        let marker = if highlight { "==> " } else { "    " };

        let _bytes_hex: String = insn.bytes.iter().map(|b| format!("{:02x}", b)).collect();

        write!(
            out,
            "{}0x{:08x}:  {:<8}{}",
            marker, insn.address, insn.mnemonic, insn.operands
        )
        .unwrap();

        // Append call target annotation if available
        if insn.is_indirect_call {
            write!(out, "              ; indirect call").unwrap();
        }

        writeln!(out).unwrap();
    }

    out
}

/// Format a "sym only" result (no binary available).
pub fn format_sym_only(module: &ModuleInfo, function: &FunctionInfo) -> String {
    format_text(
        module,
        function,
        &[],
        &DataSource::SymOnly,
        None,
    )
}
