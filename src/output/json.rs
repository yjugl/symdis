// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use serde::Serialize;

use crate::disasm::annotate::AnnotatedInstruction;

use super::text::{DataSource, FunctionInfo, ModuleInfo, SymOnlyData};

#[derive(Serialize)]
struct JsonDisasmOutput {
    module: JsonModule,
    function: JsonFunction,
    instructions: Vec<JsonInstruction>,
    source: String,
    warnings: Vec<String>,
}

#[derive(Serialize)]
struct JsonModule {
    debug_file: String,
    debug_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    code_file: Option<String>,
    arch: String,
}

#[derive(Serialize)]
struct JsonFunction {
    name: String,
    address: String,
    size: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_file: Option<String>,
}

#[derive(Serialize)]
struct JsonInstruction {
    address: String,
    bytes: String,
    mnemonic: String,
    operands: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_line: Option<u32>,
    highlighted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    call_target: Option<String>,
    inline_frames: Vec<JsonInlineFrame>,
}

#[derive(Serialize)]
struct JsonInlineFrame {
    function: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    call_file: Option<String>,
    call_line: u32,
    depth: u32,
}

#[derive(Serialize)]
struct JsonSymOnlyOutput {
    module: JsonModule,
    function: JsonFunction,
    instructions: Vec<JsonInstruction>,
    source: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    source_lines: Vec<JsonSourceLine>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    inline_frames: Vec<JsonSymOnlyInline>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    source_files: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Serialize)]
struct JsonSourceLine {
    address: String,
    size: String,
    file: String,
    line: u32,
}

#[derive(Serialize)]
struct JsonSymOnlyInline {
    address: String,
    end_address: String,
    depth: u32,
    function: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    call_file: Option<String>,
    call_line: u32,
}

#[derive(Serialize)]
struct JsonError {
    error: JsonErrorDetail,
}

#[derive(Serialize)]
struct JsonErrorDetail {
    code: String,
    message: String,
}

impl JsonModule {
    fn from_info(info: &ModuleInfo) -> Self {
        Self {
            debug_file: info.debug_file.clone(),
            debug_id: info.debug_id.clone(),
            code_file: info.code_file.clone(),
            arch: info.arch.clone(),
        }
    }
}

impl JsonFunction {
    fn from_info(info: &FunctionInfo) -> Self {
        Self {
            name: info.name.clone(),
            address: format!("0x{:x}", info.address),
            size: format!("0x{:x}", info.size),
            source_file: info.source_file.clone(),
        }
    }
}

impl JsonInstruction {
    fn from_annotated(insn: &AnnotatedInstruction) -> Self {
        let bytes_hex = insn
            .instruction
            .bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        Self {
            address: format!("0x{:x}", insn.instruction.address),
            bytes: bytes_hex,
            mnemonic: insn.instruction.mnemonic.clone(),
            operands: insn.instruction.operands.clone(),
            source_file: insn.source_file.clone(),
            source_line: insn.source_line,
            highlighted: insn.highlighted,
            call_target: insn.call_target_name.clone(),
            inline_frames: insn
                .inline_frames
                .iter()
                .map(|f| JsonInlineFrame {
                    function: f.name.clone(),
                    call_file: f.call_file.clone(),
                    call_line: f.call_line,
                    depth: f.depth,
                })
                .collect(),
        }
    }
}

/// Format disassembly output as JSON.
pub fn format_json(
    module: &ModuleInfo,
    function: &FunctionInfo,
    instructions: &[AnnotatedInstruction],
    data_source: &DataSource,
    warnings: &[String],
) -> String {
    let output = JsonDisasmOutput {
        module: JsonModule::from_info(module),
        function: JsonFunction::from_info(function),
        instructions: instructions
            .iter()
            .map(JsonInstruction::from_annotated)
            .collect(),
        source: data_source.to_string(),
        warnings: warnings.to_vec(),
    };
    serde_json::to_string_pretty(&output).expect("JSON serialization should not fail")
}

/// Format a "sym only" result as JSON (no binary available).
///
/// When `sym_data` is `Some`, includes enriched source line mapping, inline
/// frames, and source file list. When `None`, these arrays are omitted.
pub fn format_json_sym_only(
    module: &ModuleInfo,
    function: &FunctionInfo,
    sym_data: Option<&SymOnlyData>,
    data_source: &DataSource,
    warnings: &[String],
) -> String {
    let (source_lines, inline_frames, source_files) = match sym_data {
        Some(data) => {
            let sl: Vec<JsonSourceLine> = data
                .source_lines
                .iter()
                .map(|s| JsonSourceLine {
                    address: format!("0x{:x}", s.address),
                    size: format!("0x{:x}", s.size),
                    file: s.file.clone(),
                    line: s.line,
                })
                .collect();
            let inf: Vec<JsonSymOnlyInline> = data
                .inline_frames
                .iter()
                .map(|i| JsonSymOnlyInline {
                    address: format!("0x{:x}", i.address),
                    end_address: format!("0x{:x}", i.end_address),
                    depth: i.depth,
                    function: i.name.clone(),
                    call_file: i.call_file.clone(),
                    call_line: i.call_line,
                })
                .collect();
            let sf: Vec<String> = data.source_files.clone();
            (sl, inf, sf)
        }
        None => (Vec::new(), Vec::new(), Vec::new()),
    };

    let output = JsonSymOnlyOutput {
        module: JsonModule::from_info(module),
        function: JsonFunction::from_info(function),
        instructions: Vec::new(),
        source: data_source.to_string(),
        source_lines,
        inline_frames,
        source_files,
        warnings: warnings.to_vec(),
    };
    serde_json::to_string_pretty(&output).expect("JSON serialization should not fail")
}

/// Format an error as JSON.
pub fn format_json_error(message: &str) -> String {
    let output = JsonError {
        error: JsonErrorDetail {
            code: "ERROR".to_string(),
            message: message.to_string(),
        },
    };
    serde_json::to_string_pretty(&output).expect("JSON serialization should not fail")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::annotate::{AnnotatedInstruction, InlineFrame};
    use crate::disasm::engine::Instruction;

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

    fn make_annotated_instructions() -> Vec<AnnotatedInstruction> {
        vec![
            AnnotatedInstruction {
                instruction: Instruction {
                    address: 0x1a3e80,
                    size: 1,
                    bytes: vec![0x55],
                    mnemonic: "push".to_string(),
                    operands: "rbp".to_string(),
                    call_target: None,
                    is_indirect_call: false,
                    indirect_mem_addr: None,
                },
                source_file: Some("src/main.cpp".to_string()),
                source_line: Some(10),
                call_target_name: None,
                inline_frames: Vec::new(),
                highlighted: false,
            },
            AnnotatedInstruction {
                instruction: Instruction {
                    address: 0x1a3e81,
                    size: 5,
                    bytes: vec![0xe8, 0x3b, 0x84, 0x00, 0x00],
                    mnemonic: "call".to_string(),
                    operands: "0x001b2340".to_string(),
                    call_target: Some(0x1b2340),
                    is_indirect_call: false,
                    indirect_mem_addr: None,
                },
                source_file: Some("src/main.cpp".to_string()),
                source_line: Some(11),
                call_target_name: Some("CalledFunction".to_string()),
                inline_frames: vec![InlineFrame {
                    name: "InlinedHelper".to_string(),
                    call_file: Some("src/helper.cpp".to_string()),
                    call_line: 42,
                    depth: 0,
                }],
                highlighted: true,
            },
        ]
    }

    #[test]
    fn test_json_output_structure() {
        let module = make_module_info();
        let function = make_function_info();
        let instructions = make_annotated_instructions();

        let json_str = format_json(
            &module,
            &function,
            &instructions,
            &DataSource::BinaryAndSym,
            &[],
        );
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        // Top-level fields
        assert_eq!(v["source"], "binary+sym");
        assert!(v["warnings"].as_array().unwrap().is_empty());

        // Module
        assert_eq!(v["module"]["debug_file"], "test.pdb");
        assert_eq!(v["module"]["debug_id"], "AABBCCDD11223344");
        assert_eq!(v["module"]["code_file"], "test.dll");
        assert_eq!(v["module"]["arch"], "x86_64");

        // Function
        assert_eq!(v["function"]["name"], "TestFunction");
        assert_eq!(v["function"]["source_file"], "src/main.cpp");

        // Instructions array
        let insns = v["instructions"].as_array().unwrap();
        assert_eq!(insns.len(), 2);

        // Second instruction has call target and inline frame
        assert_eq!(insns[1]["call_target"], "CalledFunction");
        assert!(insns[1]["highlighted"].as_bool().unwrap());
        let frames = insns[1]["inline_frames"].as_array().unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0]["function"], "InlinedHelper");
        assert_eq!(frames[0]["call_file"], "src/helper.cpp");
        assert_eq!(frames[0]["call_line"], 42);
        assert_eq!(frames[0]["depth"], 0);
    }

    #[test]
    fn test_json_hex_addresses() {
        let module = make_module_info();
        let function = make_function_info();
        let instructions = make_annotated_instructions();

        let json_str = format_json(
            &module,
            &function,
            &instructions,
            &DataSource::BinaryAndSym,
            &[],
        );
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        // Function addresses are hex strings
        assert_eq!(v["function"]["address"], "0x1a3e80");
        assert_eq!(v["function"]["size"], "0x120");

        // Instruction addresses are hex strings
        assert_eq!(v["instructions"][0]["address"], "0x1a3e80");
        assert_eq!(v["instructions"][1]["address"], "0x1a3e81");
    }

    #[test]
    fn test_json_bytes_encoding() {
        let module = make_module_info();
        let function = make_function_info();
        let instructions = make_annotated_instructions();

        let json_str = format_json(
            &module,
            &function,
            &instructions,
            &DataSource::BinaryAndSym,
            &[],
        );
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        // Bytes are hex-encoded strings
        assert_eq!(v["instructions"][0]["bytes"], "55");
        assert_eq!(v["instructions"][1]["bytes"], "e83b840000");
    }

    #[test]
    fn test_json_skip_serializing_none() {
        let module = ModuleInfo {
            debug_file: "test.pdb".to_string(),
            debug_id: "AABB".to_string(),
            code_file: None,
            arch: "x86_64".to_string(),
        };
        let function = FunctionInfo {
            name: "Func".to_string(),
            address: 0x1000,
            size: 0x10,
            source_file: None,
        };
        let instructions = vec![AnnotatedInstruction {
            instruction: Instruction {
                address: 0x1000,
                size: 1,
                bytes: vec![0xcc],
                mnemonic: "int3".to_string(),
                operands: String::new(),
                call_target: None,
                is_indirect_call: false,
                indirect_mem_addr: None,
            },
            source_file: None,
            source_line: None,
            call_target_name: None,
            inline_frames: Vec::new(),
            highlighted: false,
        }];

        let json_str = format_json(
            &module,
            &function,
            &instructions,
            &DataSource::BinaryOnly,
            &[],
        );
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        // None fields should be absent
        assert!(v["module"]["code_file"].is_null());
        assert!(v["function"]["source_file"].is_null());
        assert!(v["instructions"][0]["source_file"].is_null());
        assert!(v["instructions"][0]["source_line"].is_null());
        assert!(v["instructions"][0]["call_target"].is_null());

        assert_eq!(v["source"], "binary");
    }

    #[test]
    fn test_json_sym_only() {
        let module = make_module_info();
        let function = make_function_info();

        let json_str = format_json_sym_only(&module, &function, None, &DataSource::SymOnly, &[]);
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(v["source"], "sym");
        assert!(v["instructions"].as_array().unwrap().is_empty());
        assert_eq!(v["function"]["name"], "TestFunction");
        // No enriched fields when sym_data is None
        assert!(v.get("source_lines").is_none());
        assert!(v.get("inline_frames").is_none());
        assert!(v.get("source_files").is_none());
    }

    #[test]
    fn test_json_sym_only_enriched() {
        use crate::output::text::{SymOnlyData, SymOnlyInline, SymOnlyLine};

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
            source_files: vec!["src/main.cpp".to_string(), "src/helper.h".to_string()],
        };

        let json_str = format_json_sym_only(
            &module,
            &function,
            Some(&sym_data),
            &DataSource::SymOnly,
            &[],
        );
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(v["source"], "sym");
        assert!(v["instructions"].as_array().unwrap().is_empty());

        // source_lines
        let sl = v["source_lines"].as_array().unwrap();
        assert_eq!(sl.len(), 2);
        assert_eq!(sl[0]["address"], "0x1a3e80");
        assert_eq!(sl[0]["size"], "0x10");
        assert_eq!(sl[0]["file"], "src/main.cpp");
        assert_eq!(sl[0]["line"], 10);

        // inline_frames
        let inf = v["inline_frames"].as_array().unwrap();
        assert_eq!(inf.len(), 1);
        assert_eq!(inf[0]["address"], "0x1a3e90");
        assert_eq!(inf[0]["end_address"], "0x1a3ec0");
        assert_eq!(inf[0]["depth"], 0);
        assert_eq!(inf[0]["function"], "InlinedHelper");
        assert_eq!(inf[0]["call_file"], "src/helper.h");
        assert_eq!(inf[0]["call_line"], 40);

        // source_files
        let sf = v["source_files"].as_array().unwrap();
        assert_eq!(sf.len(), 2);
        assert_eq!(sf[0], "src/main.cpp");
        assert_eq!(sf[1], "src/helper.h");
    }

    #[test]
    fn test_json_error_format() {
        let json_str = format_json_error("something went wrong");
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(v["error"]["code"], "ERROR");
        assert_eq!(v["error"]["message"], "something went wrong");
    }
}
