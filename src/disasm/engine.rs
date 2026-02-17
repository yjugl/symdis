// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use anyhow::Result;
use capstone::prelude::*;
use capstone::arch::x86::{X86OperandType, X86Reg};
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
    /// For indirect call/jmp with a resolvable memory operand: the RVA of the memory slot.
    /// x86-64 RIP-relative: `insn_address + insn_size + displacement`.
    /// x86 32-bit absolute: `displacement - image_base`.
    pub indirect_mem_addr: Option<u64>,
}

/// Capstone-based disassembly engine.
pub struct Disassembler {
    cs: Capstone,
    arch: CpuArch,
}

impl Disassembler {
    /// Create a new disassembler for the given architecture and syntax.
    ///
    /// When `thumb` is true and arch is `CpuArch::Arm`, Capstone is configured
    /// in Thumb mode for ARM32 Thumb-2 instruction decoding.
    pub fn new(arch: CpuArch, syntax: Syntax, thumb: bool) -> Result<Self> {
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
                let mode = if thumb {
                    arch::arm::ArchMode::Thumb
                } else {
                    arch::arm::ArchMode::Arm
                };
                Capstone::new()
                    .arm()
                    .mode(mode)
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

        Ok(Self { cs, arch })
    }

    /// Disassemble code bytes starting at base_addr.
    ///
    /// If `must_include_addr` is set and the instruction at that address would
    /// be beyond `max_instructions`, the limit is automatically extended to
    /// include it plus 200 instructions of trailing context.
    ///
    /// `image_base` is the PE image base address, used to convert absolute VAs
    /// to RVAs for x86 32-bit indirect call resolution. Pass 0 for non-PE
    /// binaries or when the binary is unavailable.
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
        image_base: u64,
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

            let (call_target, is_indirect_call, indirect_mem_addr) =
                self.extract_call_target(insn, &mnemonic, &operands, image_base);

            result.push(Instruction {
                address: insn.address(),
                size: insn.len() as u8,
                bytes: insn.bytes().to_vec(),
                mnemonic,
                operands,
                call_target,
                is_indirect_call,
                indirect_mem_addr,
            });
        }

        Ok((result, total_count))
    }

    /// Extract call/jmp target from an instruction.
    ///
    /// Returns `(call_target, is_indirect, indirect_mem_addr)`.
    fn extract_call_target(
        &self,
        insn: &capstone::Insn,
        mnemonic: &str,
        operands: &str,
        image_base: u64,
    ) -> (Option<u64>, bool, Option<u64>) {
        // Only look at call/jmp instructions
        let is_call_or_jmp = mnemonic == "call"
            || mnemonic == "jmp"
            || mnemonic == "bl"
            || mnemonic == "b"
            || mnemonic == "blr"
            || mnemonic.starts_with("callq")
            || mnemonic.starts_with("jmpq");

        if !is_call_or_jmp {
            return (None, false, None);
        }

        // Check for indirect calls (contains brackets or register names without 0x prefix)
        if operands.contains('[') || operands.contains("ptr") {
            let indirect_mem = self.extract_indirect_mem_addr(insn, image_base);
            return (None, true, indirect_mem);
        }

        // For direct calls, try to parse the target address from the operand
        // ARM/ARM64 use '#' prefix for immediates (e.g. "bl #0x1234")
        let target_str = operands.trim().trim_start_matches('#').trim_start_matches("0x");
        if let Ok(target) = u64::from_str_radix(target_str, 16) {
            return (Some(target), false, None);
        }

        // If we can't determine, it might be an indirect call to a register
        let op_trimmed = operands.trim_start_matches('#');
        if !operands.is_empty() && !op_trimmed.starts_with("0x") && !op_trimmed.starts_with("0X") {
            return (None, true, None);
        }

        (None, false, None)
    }

    /// Extract the memory slot RVA from an indirect call/jmp operand.
    ///
    /// Handles two addressing modes:
    ///
    /// **x86-64 RIP-relative**: `call qword ptr [rip + 0x1234]` at address 0x1000 (6 bytes)
    /// → slot_rva = 0x1000 + 6 + 0x1234 = 0x223a.
    ///
    /// **x86 32-bit absolute**: `call dword ptr [0x10001234]` with image_base 0x10000000
    /// → slot_rva = 0x10001234 - 0x10000000 = 0x1234.
    /// This is the standard calling convention for IAT imports on Windows x86.
    fn extract_indirect_mem_addr(&self, insn: &capstone::Insn, image_base: u64) -> Option<u64> {
        let detail = self.cs.insn_detail(insn).ok()?;
        let arch_detail = detail.arch_detail();
        let x86 = arch_detail.x86()?;

        for op in x86.operands() {
            if let X86OperandType::Mem(mem) = op.op_type {
                // x86-64: RIP-relative addressing
                if mem.base().0 == X86Reg::X86_REG_RIP as u16 {
                    let addr = insn.address() as i64 + insn.len() as i64 + mem.disp();
                    return Some(addr as u64);
                }

                // x86 32-bit: absolute addressing (no base register, no index register)
                // The displacement is the absolute VA; subtract image_base to get RVA.
                if self.arch == CpuArch::X86
                    && mem.base().0 == 0
                    && mem.index().0 == 0
                    && image_base > 0
                {
                    // Truncate to 32 bits — Capstone sign-extends the 32-bit displacement
                    // to i64, so VAs >= 0x80000000 appear negative. Cast through u32 to
                    // recover the unsigned 32-bit value.
                    let va = (mem.disp() as u32) as u64;
                    return va.checked_sub(image_base);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x86_64_disasm() {
        let disasm = Disassembler::new(CpuArch::X86_64, Syntax::Intel, false).unwrap();
        // push rbp; mov rbp, rsp; sub rsp, 0x10
        let code = [0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10];
        let (insns, total) = disasm.disassemble(&code, 0x1000, 100, None, 0).unwrap();

        assert_eq!(insns.len(), 3);
        assert_eq!(total, 3);
        assert_eq!(insns[0].mnemonic, "push");
        assert_eq!(insns[0].address, 0x1000);
        assert_eq!(insns[1].mnemonic, "mov");
        assert_eq!(insns[2].mnemonic, "sub");
    }

    #[test]
    fn test_x86_64_att_syntax() {
        let disasm = Disassembler::new(CpuArch::X86_64, Syntax::Att, false).unwrap();
        let code = [0x55]; // push rbp
        let (insns, _) = disasm.disassemble(&code, 0x1000, 100, None, 0).unwrap();

        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].mnemonic, "pushq");
        assert_eq!(insns[0].operands, "%rbp");
    }

    #[test]
    fn test_x86_32_disasm() {
        let disasm = Disassembler::new(CpuArch::X86, Syntax::Intel, false).unwrap();
        // push ebp; mov ebp, esp
        let code = [0x55, 0x89, 0xe5];
        let (insns, _) = disasm.disassemble(&code, 0x1000, 100, None, 0).unwrap();

        assert_eq!(insns.len(), 2);
        assert_eq!(insns[0].mnemonic, "push");
        assert!(insns[0].operands.contains("ebp"));
        assert_eq!(insns[1].mnemonic, "mov");
    }

    #[test]
    fn test_call_target_extraction() {
        let disasm = Disassembler::new(CpuArch::X86_64, Syntax::Intel, false).unwrap();
        // call +0x100 (E8 relative call, target = 0x1005 + 0x100 = 0x1105)
        let code = [0xe8, 0x00, 0x01, 0x00, 0x00];
        let (insns, _) = disasm.disassemble(&code, 0x1000, 100, None, 0).unwrap();

        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].mnemonic, "call");
        assert!(insns[0].call_target.is_some());
        assert_eq!(insns[0].call_target.unwrap(), 0x1105);
        assert!(!insns[0].is_indirect_call);
    }

    #[test]
    fn test_indirect_call() {
        let disasm = Disassembler::new(CpuArch::X86_64, Syntax::Intel, false).unwrap();
        // call rax (FF D0)
        let code = [0xff, 0xd0];
        let (insns, _) = disasm.disassemble(&code, 0x1000, 100, None, 0).unwrap();

        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].mnemonic, "call");
        assert!(insns[0].call_target.is_none());
        assert!(insns[0].is_indirect_call);
        // Register-indirect calls don't have a computable memory address
        assert!(insns[0].indirect_mem_addr.is_none());
    }

    #[test]
    fn test_rip_relative_call() {
        let disasm = Disassembler::new(CpuArch::X86_64, Syntax::Intel, false).unwrap();
        // FF 15 xx xx xx xx = call qword ptr [rip + disp32]
        // At address 0x1000, size 6, displacement 0x2000:
        // slot_rva = 0x1000 + 6 + 0x2000 = 0x3006
        let code = [0xff, 0x15, 0x00, 0x20, 0x00, 0x00];
        let (insns, _) = disasm.disassemble(&code, 0x1000, 100, None, 0).unwrap();

        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].mnemonic, "call");
        assert!(insns[0].call_target.is_none());
        assert!(insns[0].is_indirect_call);
        assert_eq!(insns[0].indirect_mem_addr, Some(0x3006));
    }

    #[test]
    fn test_rip_relative_jmp() {
        let disasm = Disassembler::new(CpuArch::X86_64, Syntax::Intel, false).unwrap();
        // FF 25 xx xx xx xx = jmp qword ptr [rip + disp32]
        // At address 0x2000, size 6, displacement 0x1000:
        // slot_rva = 0x2000 + 6 + 0x1000 = 0x3006
        let code = [0xff, 0x25, 0x00, 0x10, 0x00, 0x00];
        let (insns, _) = disasm.disassemble(&code, 0x2000, 100, None, 0).unwrap();

        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].mnemonic, "jmp");
        assert!(insns[0].call_target.is_none());
        assert!(insns[0].is_indirect_call);
        assert_eq!(insns[0].indirect_mem_addr, Some(0x3006));
    }

    #[test]
    fn test_x86_32_absolute_indirect_call() {
        let disasm = Disassembler::new(CpuArch::X86, Syntax::Intel, false).unwrap();
        // FF 15 xx xx xx xx = call dword ptr [disp32]
        // call dword ptr [0x10005000] with image_base 0x10000000:
        // slot_rva = 0x10005000 - 0x10000000 = 0x5000
        let code = [0xff, 0x15, 0x00, 0x50, 0x00, 0x10];
        let (insns, _) = disasm.disassemble(&code, 0x1000, 100, None, 0x10000000).unwrap();

        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].mnemonic, "call");
        assert!(insns[0].call_target.is_none());
        assert!(insns[0].is_indirect_call);
        assert_eq!(insns[0].indirect_mem_addr, Some(0x5000));
    }

    #[test]
    fn test_x86_32_absolute_indirect_call_high_va() {
        // Test with VA >= 0x80000000 (sign-extended by Capstone)
        let disasm = Disassembler::new(CpuArch::X86, Syntax::Intel, false).unwrap();
        // call dword ptr [0x80001234] with image_base 0x10000000:
        // slot_rva = 0x80001234 - 0x10000000 = 0x70001234
        let code = [0xff, 0x15, 0x34, 0x12, 0x00, 0x80];
        let (insns, _) = disasm.disassemble(&code, 0x1000, 100, None, 0x10000000).unwrap();

        assert_eq!(insns.len(), 1);
        assert!(insns[0].is_indirect_call);
        assert_eq!(insns[0].indirect_mem_addr, Some(0x70001234));
    }

    #[test]
    fn test_x86_32_register_indirect_no_resolve() {
        // call dword ptr [eax] should NOT produce an indirect_mem_addr
        let disasm = Disassembler::new(CpuArch::X86, Syntax::Intel, false).unwrap();
        // FF 10 = call dword ptr [eax]
        let code = [0xff, 0x10];
        let (insns, _) = disasm.disassemble(&code, 0x1000, 100, None, 0x10000000).unwrap();

        assert_eq!(insns.len(), 1);
        assert!(insns[0].is_indirect_call);
        assert!(insns[0].indirect_mem_addr.is_none());
    }

    #[test]
    fn test_x86_32_no_image_base_no_resolve() {
        // Without image_base (0), absolute addressing should not be resolved
        let disasm = Disassembler::new(CpuArch::X86, Syntax::Intel, false).unwrap();
        let code = [0xff, 0x15, 0x00, 0x50, 0x00, 0x10];
        let (insns, _) = disasm.disassemble(&code, 0x1000, 100, None, 0).unwrap();

        assert_eq!(insns.len(), 1);
        assert!(insns[0].is_indirect_call);
        assert!(insns[0].indirect_mem_addr.is_none());
    }

    #[test]
    fn test_max_instructions_limit() {
        let disasm = Disassembler::new(CpuArch::X86_64, Syntax::Intel, false).unwrap();
        // nop sled
        let code = vec![0x90; 100];
        let (insns, total) = disasm.disassemble(&code, 0x1000, 5, None, 0).unwrap();

        assert_eq!(insns.len(), 5);
        assert_eq!(total, 100);
    }

    #[test]
    fn test_empty_code() {
        let disasm = Disassembler::new(CpuArch::X86_64, Syntax::Intel, false).unwrap();
        let (insns, total) = disasm.disassemble(&[], 0x1000, 100, None, 0).unwrap();
        assert!(insns.is_empty());
        assert_eq!(total, 0);
    }

    #[test]
    fn test_disassemble_auto_extend_for_highlight() {
        let disasm = Disassembler::new(CpuArch::X86_64, Syntax::Intel, false).unwrap();
        // 100 nops — each is 1 byte at address 0x1000 + i
        let code = vec![0x90; 100];
        // Highlight at instruction #50 (address 0x1032), with max_instructions = 10
        let (insns, total) = disasm
            .disassemble(&code, 0x1000, 10, Some(0x1032), 0)
            .unwrap();

        assert_eq!(total, 100);
        // Should auto-extend: instruction at index 50, so limit = 50 + 201 = 251, capped at 100
        assert_eq!(insns.len(), 100);
        // The highlighted instruction should be present
        assert!(insns.iter().any(|i| i.address == 0x1032));
    }

    #[test]
    fn test_disassemble_no_extend_within_limit() {
        let disasm = Disassembler::new(CpuArch::X86_64, Syntax::Intel, false).unwrap();
        let code = vec![0x90; 100];
        // Highlight at instruction #3 (address 0x1003), within max_instructions = 10
        let (insns, total) = disasm
            .disassemble(&code, 0x1000, 10, Some(0x1003), 0)
            .unwrap();

        assert_eq!(total, 100);
        // Should NOT extend — highlight is within limit
        assert_eq!(insns.len(), 10);
    }

    #[test]
    fn test_disassemble_total_count() {
        let disasm = Disassembler::new(CpuArch::X86_64, Syntax::Intel, false).unwrap();
        let code = vec![0x90; 500];
        let (insns, total) = disasm.disassemble(&code, 0x1000, 100, None, 0).unwrap();

        assert_eq!(total, 500);
        assert_eq!(insns.len(), 100);
    }

    #[test]
    fn test_disassemble_no_highlight_backward_compat() {
        let disasm = Disassembler::new(CpuArch::X86_64, Syntax::Intel, false).unwrap();
        let code = vec![0x90; 50];
        let (insns, total) = disasm.disassemble(&code, 0x1000, 20, None, 0).unwrap();

        assert_eq!(total, 50);
        assert_eq!(insns.len(), 20);
    }

    #[test]
    fn test_arm_thumb_disasm() {
        let disasm = Disassembler::new(CpuArch::Arm, Syntax::Intel, true).unwrap();
        // Thumb-2: push {r4, r5, r6, r7, lr} = 2d e9 f0 40
        // Followed by: mov r7, r0 = 07 46 (16-bit Thumb)
        let code = [0x2d, 0xe9, 0xf0, 0x40, 0x07, 0x46];
        let (insns, _) = disasm.disassemble(&code, 0x1000, 100, None, 0).unwrap();

        assert!(insns.len() >= 2);
        assert_eq!(insns[0].mnemonic, "push.w");
        assert_eq!(insns[1].mnemonic, "mov");
    }

    #[test]
    fn test_arm_mode_disasm() {
        let disasm = Disassembler::new(CpuArch::Arm, Syntax::Intel, false).unwrap();
        // ARM: push {r4, r5, r6, r7, r8, r9, r10, r11, lr} = f0 47 2d e9
        let code = [0xf0, 0x47, 0x2d, 0xe9];
        let (insns, _) = disasm.disassemble(&code, 0x1000, 100, None, 0).unwrap();

        assert_eq!(insns.len(), 1);
        // Should decode as ARM push, not garbage
        assert!(insns[0].mnemonic == "push" || insns[0].mnemonic == "stmdb");
    }
}
