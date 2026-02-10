// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use anyhow::Result;
use capstone::prelude::*;
use tracing::info;

use crate::binary::CpuArch;
use crate::config::Syntax;

/// A disassembled instruction.
#[derive(Debug, Clone)]
pub struct Instruction {
    /// RVA of the instruction.
    pub address: u64,
    /// Size of the instruction in bytes.
    pub size: u8,
    /// Raw bytes.
    pub bytes: Vec<u8>,
    /// Mnemonic (e.g., "push", "call").
    pub mnemonic: String,
    /// Operand string (e.g., "rbp", "0x1234").
    pub operands: String,
    /// For call/jmp instructions: the absolute target address if direct.
    pub call_target: Option<u64>,
    /// Whether this is an indirect call/jmp.
    pub is_indirect_call: bool,
}

/// Capstone-based disassembly engine.
pub struct Disassembler {
    cs: Capstone,
}

impl Disassembler {
    /// Create a new disassembler for the given architecture and syntax.
    pub fn new(arch: CpuArch, syntax: Syntax) -> Result<Self> {
        let cs = match arch {
            CpuArch::X86 => {
                let mut cs = Capstone::new()
                    .x86()
                    .mode(arch::x86::ArchMode::Mode32)
                    .detail(true)
                    .build()
                    .map_err(|e| anyhow::anyhow!("capstone init: {e}"))?;
                match syntax {
                    Syntax::Intel => cs.set_syntax(capstone::Syntax::Intel),
                    Syntax::Att => cs.set_syntax(capstone::Syntax::Att),
                }
                .map_err(|e| anyhow::anyhow!("capstone set syntax: {e}"))?;
                cs
            }
            CpuArch::X86_64 => {
                let mut cs = Capstone::new()
                    .x86()
                    .mode(arch::x86::ArchMode::Mode64)
                    .detail(true)
                    .build()
                    .map_err(|e| anyhow::anyhow!("capstone init: {e}"))?;
                match syntax {
                    Syntax::Intel => cs.set_syntax(capstone::Syntax::Intel),
                    Syntax::Att => cs.set_syntax(capstone::Syntax::Att),
                }
                .map_err(|e| anyhow::anyhow!("capstone set syntax: {e}"))?;
                cs
            }
            CpuArch::Arm => {
                Capstone::new()
                    .arm()
                    .mode(arch::arm::ArchMode::Arm)
                    .detail(true)
                    .build()
                    .map_err(|e| anyhow::anyhow!("capstone init: {e}"))?
            }
            CpuArch::Arm64 => {
                Capstone::new()
                    .arm64()
                    .mode(arch::arm64::ArchMode::Arm)
                    .detail(true)
                    .build()
                    .map_err(|e| anyhow::anyhow!("capstone init: {e}"))?
            }
        };

        Ok(Self { cs })
    }

    /// Disassemble code bytes starting at base_addr.
    ///
    /// If `must_include_addr` is set and the instruction at that address would
    /// be beyond `max_instructions`, the limit is automatically extended to
    /// include it plus 200 instructions of trailing context.
    ///
    /// Returns `(instructions, total_instruction_count)` where
    /// `total_instruction_count` is the number of instructions in the full
    /// function (before any truncation).
    pub fn disassemble(
        &self,
        code: &[u8],
        base_addr: u64,
        max_instructions: usize,
        must_include_addr: Option<u64>,
    ) -> Result<(Vec<Instruction>, usize)> {
        if code.is_empty() {
            return Ok((Vec::new(), 0));
        }

        let insns = self
            .cs
            .disasm_all(code, base_addr)
            .map_err(|e| anyhow::anyhow!("disassembly failed: {e}"))?;

        let total_count = insns.as_ref().len();

        // Determine effective limit: auto-extend if must_include_addr is beyond max_instructions
        let effective_limit = if let Some(target_addr) = must_include_addr {
            let target_index = insns.as_ref().iter().position(|insn| {
                let addr = insn.address();
                let end = addr + insn.len() as u64;
                target_addr >= addr && target_addr < end
            });
            if let Some(idx) = target_index {
                if idx >= max_instructions {
                    let extended = idx + 201; // target + 200 trailing context
                    info!(
                        "auto-extending instruction limit from {} to {} to include highlight offset at instruction #{}",
                        max_instructions, extended.min(total_count), idx + 1
                    );
                    extended
                } else {
                    max_instructions
                }
            } else {
                max_instructions
            }
        } else {
            max_instructions
        };

        let mut result = Vec::new();
        for insn in insns.as_ref().iter().take(effective_limit) {
            let mnemonic = insn.mnemonic().unwrap_or("???").to_string();
            let operands = insn.op_str().unwrap_or("").to_string();

            let (call_target, is_indirect_call) =
                self.extract_call_target(insn, &mnemonic, &operands);

            result.push(Instruction {
                address: insn.address(),
                size: insn.len() as u8,
                bytes: insn.bytes().to_vec(),
                mnemonic,
                operands,
                call_target,
                is_indirect_call,
            });
        }

        Ok((result, total_count))
    }

    /// Extract call/jmp target from an instruction.
    fn extract_call_target(
        &self,
        _insn: &capstone::Insn,
        mnemonic: &str,
        operands: &str,
    ) -> (Option<u64>, bool) {
        // Only look at call/jmp instructions
        let is_call_or_jmp = mnemonic == "call"
            || mnemonic == "jmp"
            || mnemonic == "bl"
            || mnemonic == "b"
            || mnemonic == "blr"
            || mnemonic.starts_with("callq")
            || mnemonic.starts_with("jmpq");

        if !is_call_or_jmp {
            return (None, false);
        }

        // Check for indirect calls (contains brackets or register names without 0x prefix)
        if operands.contains('[') || operands.contains("ptr") {
            return (None, true);
        }

        // For direct calls, try to parse the target address from the operand
        let target_str = operands.trim().trim_start_matches("0x");
        if let Ok(target) = u64::from_str_radix(target_str, 16) {
            return (Some(target), false);
        }

        // If we can't determine, it might be an indirect call to a register
        if !operands.is_empty() && !operands.starts_with("0x") && !operands.starts_with("0X") {
            return (None, true);
        }

        (None, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x86_64_disasm() {
        let disasm = Disassembler::new(CpuArch::X86_64, Syntax::Intel).unwrap();
        // push rbp; mov rbp, rsp; sub rsp, 0x10
        let code = [0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10];
        let (insns, total) = disasm.disassemble(&code, 0x1000, 100, None).unwrap();

        assert_eq!(insns.len(), 3);
        assert_eq!(total, 3);
        assert_eq!(insns[0].mnemonic, "push");
        assert_eq!(insns[0].address, 0x1000);
        assert_eq!(insns[1].mnemonic, "mov");
        assert_eq!(insns[2].mnemonic, "sub");
    }

    #[test]
    fn test_x86_64_att_syntax() {
        let disasm = Disassembler::new(CpuArch::X86_64, Syntax::Att).unwrap();
        let code = [0x55]; // push rbp
        let (insns, _) = disasm.disassemble(&code, 0x1000, 100, None).unwrap();

        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].mnemonic, "pushq");
        assert_eq!(insns[0].operands, "%rbp");
    }

    #[test]
    fn test_x86_32_disasm() {
        let disasm = Disassembler::new(CpuArch::X86, Syntax::Intel).unwrap();
        // push ebp; mov ebp, esp
        let code = [0x55, 0x89, 0xe5];
        let (insns, _) = disasm.disassemble(&code, 0x1000, 100, None).unwrap();

        assert_eq!(insns.len(), 2);
        assert_eq!(insns[0].mnemonic, "push");
        assert!(insns[0].operands.contains("ebp"));
        assert_eq!(insns[1].mnemonic, "mov");
    }

    #[test]
    fn test_call_target_extraction() {
        let disasm = Disassembler::new(CpuArch::X86_64, Syntax::Intel).unwrap();
        // call +0x100 (E8 relative call, target = 0x1005 + 0x100 = 0x1105)
        let code = [0xe8, 0x00, 0x01, 0x00, 0x00];
        let (insns, _) = disasm.disassemble(&code, 0x1000, 100, None).unwrap();

        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].mnemonic, "call");
        assert!(insns[0].call_target.is_some());
        assert_eq!(insns[0].call_target.unwrap(), 0x1105);
        assert!(!insns[0].is_indirect_call);
    }

    #[test]
    fn test_indirect_call() {
        let disasm = Disassembler::new(CpuArch::X86_64, Syntax::Intel).unwrap();
        // call rax (FF D0)
        let code = [0xff, 0xd0];
        let (insns, _) = disasm.disassemble(&code, 0x1000, 100, None).unwrap();

        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].mnemonic, "call");
        assert!(insns[0].call_target.is_none());
        assert!(insns[0].is_indirect_call);
    }

    #[test]
    fn test_max_instructions_limit() {
        let disasm = Disassembler::new(CpuArch::X86_64, Syntax::Intel).unwrap();
        // nop sled
        let code = vec![0x90; 100];
        let (insns, total) = disasm.disassemble(&code, 0x1000, 5, None).unwrap();

        assert_eq!(insns.len(), 5);
        assert_eq!(total, 100);
    }

    #[test]
    fn test_empty_code() {
        let disasm = Disassembler::new(CpuArch::X86_64, Syntax::Intel).unwrap();
        let (insns, total) = disasm.disassemble(&[], 0x1000, 100, None).unwrap();
        assert!(insns.is_empty());
        assert_eq!(total, 0);
    }

    #[test]
    fn test_disassemble_auto_extend_for_highlight() {
        let disasm = Disassembler::new(CpuArch::X86_64, Syntax::Intel).unwrap();
        // 100 nops — each is 1 byte at address 0x1000 + i
        let code = vec![0x90; 100];
        // Highlight at instruction #50 (address 0x1032), with max_instructions = 10
        let (insns, total) = disasm
            .disassemble(&code, 0x1000, 10, Some(0x1032))
            .unwrap();

        assert_eq!(total, 100);
        // Should auto-extend: instruction at index 50, so limit = 50 + 201 = 251, capped at 100
        assert_eq!(insns.len(), 100);
        // The highlighted instruction should be present
        assert!(insns.iter().any(|i| i.address == 0x1032));
    }

    #[test]
    fn test_disassemble_no_extend_within_limit() {
        let disasm = Disassembler::new(CpuArch::X86_64, Syntax::Intel).unwrap();
        let code = vec![0x90; 100];
        // Highlight at instruction #3 (address 0x1003), within max_instructions = 10
        let (insns, total) = disasm
            .disassemble(&code, 0x1000, 10, Some(0x1003))
            .unwrap();

        assert_eq!(total, 100);
        // Should NOT extend — highlight is within limit
        assert_eq!(insns.len(), 10);
    }

    #[test]
    fn test_disassemble_total_count() {
        let disasm = Disassembler::new(CpuArch::X86_64, Syntax::Intel).unwrap();
        let code = vec![0x90; 500];
        let (insns, total) = disasm.disassemble(&code, 0x1000, 100, None).unwrap();

        assert_eq!(total, 500);
        assert_eq!(insns.len(), 100);
    }

    #[test]
    fn test_disassemble_no_highlight_backward_compat() {
        let disasm = Disassembler::new(CpuArch::X86_64, Syntax::Intel).unwrap();
        let code = vec![0x90; 50];
        let (insns, total) = disasm.disassemble(&code, 0x1000, 20, None).unwrap();

        assert_eq!(total, 50);
        assert_eq!(insns.len(), 20);
    }
}
