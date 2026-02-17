// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use crate::binary::BinaryFile;
use crate::disasm::engine::Instruction;
use crate::symbols::breakpad::{FuncRecord, SymFile};

/// An instruction with annotations from the symbol file and binary.
#[derive(Debug, Clone)]
pub struct AnnotatedInstruction {
    pub instruction: Instruction,
    /// Source file path for this instruction's address.
    pub source_file: Option<String>,
    /// Source line number.
    pub source_line: Option<u32>,
    /// Resolved name of the call/jump target, if any.
    pub call_target_name: Option<String>,
    /// Inline function frames active at this address, sorted outermost-first.
    pub inline_frames: Vec<InlineFrame>,
    /// Whether this instruction is the highlighted one.
    pub highlighted: bool,
}

/// An active inline frame at a given address.
#[derive(Debug, Clone)]
pub struct InlineFrame {
    /// The inlined function name.
    pub name: String,
    /// Source file where the inline call site is.
    pub call_file: Option<String>,
    /// Line number of the inline call site.
    pub call_line: u32,
    /// Nesting depth (0 = directly inlined into parent function).
    pub depth: u32,
}

/// Run the full annotation pipeline on a list of instructions.
///
/// Pipeline order: source lines → call targets → inlines → highlight.
pub fn annotate(
    instructions: Vec<Instruction>,
    sym: Option<&SymFile>,
    func: Option<&FuncRecord>,
    binary: Option<&dyn BinaryFile>,
    highlight_offset: Option<u64>,
) -> Vec<AnnotatedInstruction> {
    let mut result: Vec<AnnotatedInstruction> = instructions
        .into_iter()
        .map(|insn| {
            // Match highlight within instruction range, not just at start.
            // Crash reporters often subtract 1 from return addresses for non-frame-0
            // frames, placing the address inside the calling instruction.
            let highlighted = highlight_offset
                .is_some_and(|h| h >= insn.address && h < insn.address + insn.size as u64);
            AnnotatedInstruction {
                instruction: insn,
                source_file: None,
                source_line: None,
                call_target_name: None,
                inline_frames: Vec::new(),
                highlighted,
            }
        })
        .collect();

    if let (Some(sym), Some(func)) = (sym, func) {
        annotate_source_lines(&mut result, sym, func);
        annotate_inlines(&mut result, sym, func);
    }

    // Call targets can be resolved from sym even without a func record
    if let Some(sym) = sym {
        annotate_call_targets(&mut result, sym, binary);
    }

    result
}

/// Annotate instructions with source file and line from the sym file's line records.
fn annotate_source_lines(
    insns: &mut [AnnotatedInstruction],
    sym: &SymFile,
    func: &FuncRecord,
) {
    for insn in insns.iter_mut() {
        if let Some(loc) = sym.get_source_line(insn.instruction.address, func) {
            insn.source_file = Some(loc.file);
            insn.source_line = Some(loc.line);
        }
    }
}

/// Format an import as "dll!name" or just "name" if the DLL is empty.
/// ELF PLT imports have no DLL name, so we skip the prefix for cleaner output.
fn format_import(dll: &str, name: &str) -> String {
    if dll.is_empty() {
        name.to_string()
    } else {
        format!("{dll}!{name}")
    }
}

/// Annotate call/jmp instructions with resolved target names.
fn annotate_call_targets(
    insns: &mut [AnnotatedInstruction],
    sym: &SymFile,
    binary: Option<&dyn BinaryFile>,
) {
    for insn in insns.iter_mut() {
        // Direct calls: resolve target address through imports or sym file.
        // Import resolution is checked first because it gives specific names
        // (e.g., "memcpy") whereas sym resolution of PLT stub addresses yields
        // generic section names (e.g., "<.plt ELF section in libxul.so>").
        if let Some(target) = insn.instruction.call_target {
            if let Some(binary) = binary {
                if let Some((dll, name)) = binary.resolve_import(target) {
                    insn.call_target_name = Some(format_import(&dll, &name));
                    continue;
                }
            }
            if let Some(info) = sym.resolve_address(target) {
                insn.call_target_name = Some(info.name);
                continue;
            }
        }

        // Indirect calls with a known memory slot RVA (RIP-relative or absolute addressing)
        if insn.instruction.is_indirect_call {
            if let Some(slot_rva) = insn.instruction.indirect_mem_addr {
                // 1. Try IAT import resolution
                if let Some(binary) = binary {
                    if let Some((dll, name)) = binary.resolve_import(slot_rva) {
                        insn.call_target_name = Some(format_import(&dll, &name));
                        continue;
                    }
                }
                // 2. Try reading the on-disk pointer and resolving as an intra-module target
                if let Some(binary) = binary {
                    if let Some(target_rva) = binary.read_pointer_at_rva(slot_rva) {
                        if let Some(info) = sym.resolve_address(target_rva) {
                            insn.call_target_name = Some(info.name);
                            continue;
                        }
                    }
                }
            }
            // Fall through: mark as [indirect]
            if insn.call_target_name.is_none() {
                insn.call_target_name = Some("[indirect]".to_string());
            }
        }
    }
}

/// Annotate instructions with inline function frame information.
fn annotate_inlines(
    insns: &mut [AnnotatedInstruction],
    sym: &SymFile,
    func: &FuncRecord,
) {
    for insn in insns.iter_mut() {
        let frames = sym.get_inline_at(insn.instruction.address, func);
        insn.inline_frames = frames
            .into_iter()
            .map(|f| InlineFrame {
                name: f.name,
                call_file: f.call_file,
                call_line: f.call_line,
                depth: f.depth,
            })
            .collect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn make_test_sym() -> SymFile {
        let data = "\
MODULE windows x86_64 AABB test.pdb
FILE 0 src/main.cpp
FILE 1 src/helper.cpp
INLINE_ORIGIN 0 HelperFunc
FUNC 1000 80 0 TestFunction
1000 10 10 0
1010 20 11 0
1030 10 12 0
1040 10 50 1
1050 30 13 0
INLINE 0 42 1 0 1040 10
FUNC 2000 40 0 CalledFunction
2000 40 20 0
PUBLIC 3000 0 _PublicSymbol
";
        SymFile::parse(Cursor::new(data)).unwrap()
    }

    fn make_instructions(specs: &[(u64, &str, &str)]) -> Vec<Instruction> {
        specs
            .iter()
            .map(|(addr, mnemonic, operands)| Instruction {
                address: *addr,
                size: 4,
                bytes: vec![0; 4],
                mnemonic: mnemonic.to_string(),
                operands: operands.to_string(),
                call_target: None,
                is_indirect_call: false,
                indirect_mem_addr: None,
            })
            .collect()
    }

    #[test]
    fn test_source_line_annotation() {
        let sym = make_test_sym();
        let func = sym.find_function_by_name("TestFunction").unwrap();

        let instructions = make_instructions(&[
            (0x1000, "push", "rbp"),
            (0x1008, "mov", "rbp, rsp"),
            (0x1010, "sub", "rsp, 0x20"),
            (0x1030, "mov", "rax, rcx"),
        ]);

        let annotated = annotate(instructions, Some(&sym), Some(func), None, None);

        assert_eq!(annotated[0].source_file.as_deref(), Some("src/main.cpp"));
        assert_eq!(annotated[0].source_line, Some(10));
        assert_eq!(annotated[2].source_line, Some(11));
        assert_eq!(annotated[3].source_line, Some(12));
    }

    #[test]
    fn test_call_target_resolution_func() {
        let sym = make_test_sym();
        let func = sym.find_function_by_name("TestFunction").unwrap();

        let mut instructions = make_instructions(&[(0x1050, "call", "0x2000")]);
        instructions[0].call_target = Some(0x2000);

        let annotated = annotate(instructions, Some(&sym), Some(func), None, None);

        assert_eq!(
            annotated[0].call_target_name.as_deref(),
            Some("CalledFunction")
        );
    }

    #[test]
    fn test_call_target_resolution_public() {
        let sym = make_test_sym();
        let func = sym.find_function_by_name("TestFunction").unwrap();

        let mut instructions = make_instructions(&[(0x1050, "call", "0x3010")]);
        instructions[0].call_target = Some(0x3010);

        let annotated = annotate(instructions, Some(&sym), Some(func), None, None);

        assert_eq!(
            annotated[0].call_target_name.as_deref(),
            Some("_PublicSymbol")
        );
    }

    #[test]
    fn test_direct_call_import_takes_precedence_over_sym() {
        use crate::binary::CpuArch;

        /// Stub binary that resolves address 0x2000 as an import.
        struct StubBinaryWithPltImport;
        impl BinaryFile for StubBinaryWithPltImport {
            fn arch(&self) -> CpuArch { CpuArch::Arm64 }
            fn extract_code(&self, _rva: u64, _size: u64) -> anyhow::Result<Vec<u8>> { Ok(Vec::new()) }
            fn resolve_import(&self, rva: u64) -> Option<(String, String)> {
                if rva == 0x2000 {
                    Some(("".to_string(), "memcpy".to_string()))
                } else {
                    None
                }
            }
            fn exports(&self) -> &[(u64, String)] { &[] }
        }

        let sym = make_test_sym();
        let func = sym.find_function_by_name("TestFunction").unwrap();

        // Address 0x2000 matches both "CalledFunction" in sym and "memcpy" as import.
        // Import should win because it's more specific (PLT stub → actual import name).
        let mut instructions = make_instructions(&[(0x1050, "bl", "0x2000")]);
        instructions[0].call_target = Some(0x2000);

        let binary = StubBinaryWithPltImport;
        let annotated = annotate(instructions, Some(&sym), Some(func), Some(&binary), None);

        // ELF imports use empty DLL name, so just the function name is shown
        assert_eq!(
            annotated[0].call_target_name.as_deref(),
            Some("memcpy")
        );
    }

    #[test]
    fn test_indirect_call_annotation() {
        let sym = make_test_sym();
        let func = sym.find_function_by_name("TestFunction").unwrap();

        let mut instructions = make_instructions(&[(0x1050, "call", "rax")]);
        instructions[0].is_indirect_call = true;

        let annotated = annotate(instructions, Some(&sym), Some(func), None, None);

        assert_eq!(
            annotated[0].call_target_name.as_deref(),
            Some("[indirect]")
        );
    }

    #[test]
    fn test_inline_annotation() {
        let sym = make_test_sym();
        let func = sym.find_function_by_name("TestFunction").unwrap();

        let instructions = make_instructions(&[
            (0x1030, "mov", "rax, rcx"),   // not inlined
            (0x1040, "call", "something"), // inside inline HelperFunc
            (0x1050, "ret", ""),           // back to non-inlined
        ]);

        let annotated = annotate(instructions, Some(&sym), Some(func), None, None);

        assert!(annotated[0].inline_frames.is_empty());
        assert_eq!(annotated[1].inline_frames.len(), 1);
        assert_eq!(annotated[1].inline_frames[0].name, "HelperFunc");
        assert_eq!(
            annotated[1].inline_frames[0].call_file.as_deref(),
            Some("src/helper.cpp")
        );
        assert_eq!(annotated[1].inline_frames[0].call_line, 42);
        assert!(annotated[2].inline_frames.is_empty());
    }

    #[test]
    fn test_highlight_offset_exact() {
        let instructions = make_instructions(&[
            (0x1000, "push", "rbp"),
            (0x1004, "mov", "rbp, rsp"),
            (0x1010, "sub", "rsp, 0x20"),
        ]);

        let annotated = annotate(instructions, None, None, None, Some(0x1004));

        assert!(!annotated[0].highlighted);
        assert!(annotated[1].highlighted);
        assert!(!annotated[2].highlighted);
    }

    #[test]
    fn test_highlight_offset_mid_instruction() {
        // Crash reporters subtract 1 from return addresses for non-frame-0 frames,
        // placing the highlight inside the instruction rather than at its start.
        let instructions = make_instructions(&[
            (0x1000, "push", "rbp"),
            (0x1004, "call", "0x2000"),  // 4 bytes: 0x1004..0x1008
            (0x1008, "mov", "rax, rbx"),
        ]);

        // Highlight at 0x1007 (inside the call at 0x1004)
        let annotated = annotate(instructions, None, None, None, Some(0x1007));

        assert!(!annotated[0].highlighted);
        assert!(annotated[1].highlighted);
        assert!(!annotated[2].highlighted);
    }

    #[test]
    fn test_no_sym_no_annotations() {
        let instructions = make_instructions(&[
            (0x1000, "push", "rbp"),
            (0x1004, "mov", "rbp, rsp"),
        ]);

        let annotated = annotate(instructions, None, None, None, Some(0x1000));

        assert!(annotated[0].source_file.is_none());
        assert!(annotated[0].call_target_name.is_none());
        assert!(annotated[0].inline_frames.is_empty());
        assert!(annotated[0].highlighted);
        assert!(!annotated[1].highlighted);
    }

    #[test]
    fn test_unresolved_direct_call_no_annotation() {
        // Call to an address far from any symbol — should not resolve
        // (PUBLIC symbols are capped at 64KB distance in resolve_address)
        let sym = make_test_sym();
        let func = sym.find_function_by_name("TestFunction").unwrap();

        let mut instructions = make_instructions(&[(0x1050, "call", "0xdeadbeef")]);
        instructions[0].call_target = Some(0xdeadbeef);

        let annotated = annotate(instructions, Some(&sym), Some(func), None, None);

        assert!(annotated[0].call_target_name.is_none());
        assert!(!annotated[0].instruction.is_indirect_call);
    }

    #[test]
    fn test_indirect_call_resolved_via_import() {
        use crate::binary::CpuArch;

        /// Stub binary with a single IAT import.
        struct StubBinaryWithImport;
        impl BinaryFile for StubBinaryWithImport {
            fn arch(&self) -> CpuArch { CpuArch::X86_64 }
            fn extract_code(&self, _rva: u64, _size: u64) -> anyhow::Result<Vec<u8>> { Ok(Vec::new()) }
            fn resolve_import(&self, rva: u64) -> Option<(String, String)> {
                if rva == 0x8000 {
                    Some(("kernel32.dll".to_string(), "CreateFileW".to_string()))
                } else {
                    None
                }
            }
            fn exports(&self) -> &[(u64, String)] { &[] }
        }

        let sym = make_test_sym();
        let func = sym.find_function_by_name("TestFunction").unwrap();

        let mut instructions = make_instructions(&[(0x1050, "call", "qword ptr [rip + 0x1234]")]);
        instructions[0].is_indirect_call = true;
        instructions[0].indirect_mem_addr = Some(0x8000);

        let binary = StubBinaryWithImport;
        let annotated = annotate(instructions, Some(&sym), Some(func), Some(&binary), None);

        assert_eq!(
            annotated[0].call_target_name.as_deref(),
            Some("kernel32.dll!CreateFileW")
        );
    }

    #[test]
    fn test_indirect_call_resolved_via_pointer() {
        use crate::binary::CpuArch;

        /// Stub binary whose on-disk pointer at RVA 0x9000 points to RVA 0x2000.
        struct StubBinaryWithPointer;
        impl BinaryFile for StubBinaryWithPointer {
            fn arch(&self) -> CpuArch { CpuArch::X86_64 }
            fn extract_code(&self, _rva: u64, _size: u64) -> anyhow::Result<Vec<u8>> { Ok(Vec::new()) }
            fn resolve_import(&self, _rva: u64) -> Option<(String, String)> { None }
            fn exports(&self) -> &[(u64, String)] { &[] }
            fn read_pointer_at_rva(&self, rva: u64) -> Option<u64> {
                if rva == 0x9000 { Some(0x2000) } else { None }
            }
        }

        let sym = make_test_sym();
        let func = sym.find_function_by_name("TestFunction").unwrap();

        let mut instructions = make_instructions(&[(0x1050, "call", "qword ptr [rip + 0x1234]")]);
        instructions[0].is_indirect_call = true;
        instructions[0].indirect_mem_addr = Some(0x9000);

        let binary = StubBinaryWithPointer;
        let annotated = annotate(instructions, Some(&sym), Some(func), Some(&binary), None);

        // RVA 0x2000 resolves to CalledFunction in our test sym
        assert_eq!(
            annotated[0].call_target_name.as_deref(),
            Some("CalledFunction")
        );
    }

    #[test]
    fn test_indirect_call_unresolved_with_mem_addr() {
        // indirect_mem_addr is set but doesn't match any import or pointer
        let sym = make_test_sym();
        let func = sym.find_function_by_name("TestFunction").unwrap();

        let mut instructions = make_instructions(&[(0x1050, "call", "qword ptr [rip + 0x1234]")]);
        instructions[0].is_indirect_call = true;
        instructions[0].indirect_mem_addr = Some(0xFFFF);

        let annotated = annotate(instructions, Some(&sym), Some(func), None, None);

        // Falls through to [indirect]
        assert_eq!(
            annotated[0].call_target_name.as_deref(),
            Some("[indirect]")
        );
    }
}
