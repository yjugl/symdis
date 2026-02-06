# symdis — Implementation Plan

**Progressive build plan from empty project to full specification.**

Each phase produces a working (if incomplete) tool. Later phases build on earlier ones.
Phases are designed so that the tool is useful as early as Phase 6.

---

## Phase 0: Project Bootstrap

**Goal:** Cargo project compiles and runs. CLI skeleton parses arguments but does nothing yet.

### Tasks

1. **Initialize Cargo project.**
   ```
   cargo init --name symdis
   ```

2. **Add initial dependencies to `Cargo.toml`.**
   ```toml
   [dependencies]
   clap = { version = "4", features = ["derive"] }
   anyhow = "1"
   tokio = { version = "1", features = ["full"] }
   serde = { version = "1", features = ["derive"] }
   serde_json = "1"
   ```

3. **Define the CLI structure with clap derive in `src/main.rs`.**
   - Top-level `Cli` struct with subcommands: `disasm`, `lookup`, `info`, `fetch`, `frames`, `cache`.
   - Each subcommand as a struct with its parameters from the spec.
   - Global options: `--cache-dir`, `--format`, `--verbose`.
   - Each subcommand prints a "not yet implemented" message and exits.

4. **Create the module directory structure.**
   Create all `mod.rs` files so the project structure from the spec exists, with stub modules:
   ```
   src/commands/{mod,disasm,lookup,info,fetch,frames,cache}.rs
   src/symbols/{mod,breakpad,resolver,id_convert}.rs
   src/fetch/{mod,tecken,microsoft,debuginfod,cache}.rs
   src/binary/{mod,pe,elf,macho}.rs
   src/disasm/{mod,engine,annotate}.rs
   src/output/{mod,text,json}.rs
   src/crash_report.rs
   ```

5. **Set up error handling pattern.**
   Define a top-level `Result` alias using `anyhow::Result`. Establish the pattern: commands return `Result<()>`, errors bubble up with context via `.context("...")`.

6. **Set up config structure.**
   Define a `Config` struct in `src/config.rs` that holds all resolved configuration (cache dir, server URLs, output format, etc.) with `Default` impl using the built-in defaults from the spec.

### Acceptance Criteria

- `cargo build` succeeds.
- `symdis --help` shows all subcommands and global options.
- `symdis disasm --help` shows all disasm parameters.
- `symdis disasm --debug-file xul.pdb --debug-id ABC123 --offset 0x1000` prints "not yet implemented" and exits 0.

---

## Phase 1: Cache Infrastructure

**Goal:** Files can be stored in and retrieved from the local cache. Cache directory is resolved per the spec's precedence rules.

### Tasks

1. **Implement cache directory resolution** in `src/fetch/cache.rs`.
   - Parse `--cache-dir` CLI option.
   - Read `SYMDIS_CACHE_DIR` env var.
   - Parse `_NT_SYMBOL_PATH` env var (Windows): extract the first local path from `SRV*<cache>*<server>` entries.
   - Fall back to platform defaults (`%LOCALAPPDATA%\symdis\cache`, `~/.cache/symdis`, `~/Library/Caches/symdis`).
   - Use the `dirs` crate for platform-specific paths.

2. **Implement cache key types.**
   Define types that represent the two kinds of cache keys:
   - `SymbolCacheKey { debug_file, debug_id, filename }` — for `.sym` files.
   - `BinaryCacheKey { code_file, code_id, filename }` — for native binaries.

3. **Implement `Cache` struct with core operations.**
   - `get(key) -> Option<PathBuf>`: Returns the path if the file exists in cache.
   - `get_or_miss(key) -> CacheResult { Hit(PathBuf), Miss, NegativeHit }`: Also checks for `.miss` markers (returns `NegativeHit` if the marker exists and is within TTL).
   - `store(key, data: &[u8]) -> Result<PathBuf>`: Write data atomically (temp file + rename).
   - `store_miss(key) -> Result<()>`: Write a `.miss` marker.
   - `remove(key) -> Result<()>`: Remove a cached file.

4. **Implement atomic file writes.**
   Write to a `.tmp` file in the same directory, then rename. Handle the case where the parent directory doesn't exist (create it). On Windows, handle the fact that rename-over-existing may fail (delete-then-rename).

5. **Implement the `cache` subcommand.**
   - `cache path`: Print resolved cache directory.
   - `cache size`: Walk the cache directory, sum file sizes, print human-readable total.
   - `cache clear`: Delete the cache directory contents. With `--older-than <DAYS>`, filter by mtime.
   - `cache list --debug-file <NAME>`: Glob for matching entries.

### Dependencies to add

```toml
dirs = "6"
```

### Acceptance Criteria

- `symdis cache path` prints a valid directory path.
- Writing a file to cache and reading it back returns identical bytes.
- Miss markers are respected: after `store_miss`, `get_or_miss` returns `NegativeHit`.
- Miss markers expire: after TTL, `get_or_miss` returns `Miss`.
- `symdis cache size` reports `0 B` on an empty cache.
- `symdis cache clear` removes all cached files.

### Tests

- Unit tests for cache key → path mapping.
- Unit tests for `_NT_SYMBOL_PATH` parsing (cover: simple `SRV*local*remote`, chained stores, no `SRV` prefix, empty string).
- Unit tests for atomic write (simulate concurrent writes, verify no corruption).
- Integration test: full round-trip store → get.

---

## Phase 2: HTTP Fetching & Symbol Server Clients

**Goal:** Can download files from Mozilla Tecken and Microsoft Symbol Server. Downloads go to cache.

### Tasks

1. **Build the HTTP client foundation** in `src/fetch/mod.rs`.
   - Create a shared `reqwest::Client` with:
     - Configurable timeout (default: 30s).
     - User-Agent header: `symdis/<version>`.
     - Redirect policy: follow up to 10 redirects (needed for Tecken's 302s).
     - Gzip decompression enabled.
   - Define a `FetchResult` enum: `Ok(bytes)`, `NotFound`, `Error(details)`.
   - Implement `download_to_cache(url, cache_key) -> FetchResult`: download, store in cache atomically, return path.

2. **Implement the Mozilla Tecken client** in `src/fetch/tecken.rs`.
   - `fetch_sym(debug_file, debug_id) -> FetchResult`: Construct URL `<base>/<debug_file>/<debug_id>/<stem>.sym`, download.
     - The `.sym` filename stem: strip the extension from `debug_file` and append `.sym`. E.g., `xul.pdb` → `xul.sym`, `libxul.so` → `libxul.so.sym` (Breakpad convention: for files without a `.pdb` extension, append `.sym` to the full name).
   - `fetch_binary_by_code_id(code_file, code_id) -> FetchResult`: Construct URL `<base>/<code_file>/<code_id>/<code_file>`, download.

3. **Implement the Microsoft Symbol Server client** in `src/fetch/microsoft.rs`.
   - `fetch_pe(pe_name, timestamp_size) -> FetchResult`:
     1. Try uncompressed: `<base>/<pe_name>/<timestamp_size>/<pe_name>`.
     2. If 404, try compressed: `<base>/<pe_name>/<timestamp_size>/<pe_name_compressed>` (last char of extension → `_`).
     3. If compressed variant found, decompress CAB archive to get the original file.
   - `fetch_pdb(pdb_name, guid_age) -> FetchResult`: Same pattern with PDB naming.
   - CAB decompression: use the `cab` crate.

4. **Implement the unified fetch orchestrator** in `src/fetch/mod.rs`.
   - `fetch_sym_file(debug_file, debug_id) -> Result<PathBuf>`:
     1. Check cache.
     2. Try Tecken.
     3. Cache miss marker on total failure.
   - `fetch_binary(module_id) -> Result<PathBuf>`:
     1. Check cache.
     2. Try Tecken (code-file/code-id).
     3. Try Microsoft (timestamp+size for PE).
     4. Cache miss marker on total failure.
   - Both return the local path on success.

5. **Implement the `fetch` subcommand.**
   Wire up: parse args → call `fetch_sym_file` + `fetch_binary` concurrently → report results.

### Dependencies to add

```toml
reqwest = { version = "0.12", features = ["gzip", "rustls-tls"] }
cab = "0.7"
```

### Acceptance Criteria

- `symdis fetch --debug-file ntdll.pdb --debug-id <real_id>` successfully downloads `ntdll.sym` from Tecken (or reports not found).
- `symdis fetch --debug-file ntdll.pdb --debug-id <real_id> --code-file ntdll.dll --code-id <real_code_id>` downloads both the `.sym` and the `.dll`.
- A second `fetch` for the same module hits the cache (no HTTP request; verify with `--verbose`).
- A fetch for a nonexistent module stores a miss marker and doesn't re-fetch on the next attempt (until TTL expires).
- Compressed (`.dl_` / `.pd_`) downloads from Microsoft are decompressed correctly.

### Tests

- Unit tests for URL construction (Tecken sym URL, Tecken binary URL, Microsoft PE URL, Microsoft compressed variant URL).
- Unit tests for `.sym` filename derivation (`xul.pdb` → `xul.sym`, `libxul.so` → `libxul.so.sym`, `XUL` → `XUL.sym`).
- Integration test with a mock HTTP server: serve a known file, verify it lands in cache correctly.
- Integration test for CAB decompression: create a minimal CAB, decompress, verify contents.
- Integration test for redirect following (Tecken 302 pattern).

---

## Phase 3: Breakpad .sym File Parser

**Goal:** Parse `.sym` files into a structured, queryable in-memory representation.

### Tasks

1. **Define data structures** in `src/symbols/breakpad.rs`.

   ```rust
   pub struct SymFile {
       pub module: ModuleRecord,
       pub files: Vec<String>,           // indexed by FILE record number
       pub functions: Vec<FuncRecord>,    // sorted by address
       pub publics: Vec<PublicRecord>,    // sorted by address
       pub inline_origins: Vec<String>,   // indexed by INLINE_ORIGIN number
   }

   pub struct ModuleRecord {
       pub os: String,        // "windows", "linux", "mac"
       pub arch: String,      // "x86", "x86_64", "arm", "arm64"
       pub debug_id: String,
       pub name: String,
   }

   pub struct FuncRecord {
       pub address: u64,
       pub size: u64,
       pub name: String,
       pub lines: Vec<LineRecord>,     // sorted by address
       pub inlines: Vec<InlineRecord>,
   }

   pub struct LineRecord {
       pub address: u64,
       pub size: u64,
       pub line: u32,
       pub file_index: usize,
   }

   pub struct InlineRecord {
       pub depth: u32,
       pub call_line: u32,
       pub call_file_index: usize,
       pub origin_index: usize,
       pub ranges: Vec<(u64, u64)>,  // (address, size) pairs
   }

   pub struct PublicRecord {
       pub address: u64,
       pub name: String,
   }
   ```

2. **Implement the parser.**
   - Parse line-by-line (`.sym` files are line-oriented ASCII text).
   - Handle: `MODULE`, `FILE`, `FUNC`, line records (no prefix, follow a `FUNC`), `PUBLIC`, `INLINE_ORIGIN`, `INLINE`, `STACK CFI`, `STACK WIN`.
   - Skip `STACK` records for now (not needed for disassembly annotation).
   - All addresses in `.sym` files are hex without `0x` prefix. Parse with `u64::from_str_radix(s, 16)`.
   - `FUNC` and `PUBLIC` may have an optional `m` flag after the keyword (means "multiple"). Parse and ignore it.

3. **Implement query methods on `SymFile`.**
   - `find_function_by_name(name: &str) -> Option<&FuncRecord>`: Exact match on function name.
   - `find_function_by_name_fuzzy(pattern: &str) -> Vec<&FuncRecord>`: Substring match, return all matches.
   - `find_function_at_address(addr: u64) -> Option<&FuncRecord>`: Binary search `functions` for the FUNC whose range `[address, address+size)` contains `addr`.
   - `find_public_at_address(addr: u64) -> Option<&PublicRecord>`: Binary search for the PUBLIC symbol at or just before `addr`.
   - `resolve_address(addr: u64) -> Option<SymbolInfo>`: Try `find_function_at_address` first, fall back to `find_public_at_address`. Return function name + offset within function.
   - `get_source_line(addr: u64, func: &FuncRecord) -> Option<SourceLocation>`: Search the function's line records for the line covering `addr`.
   - `get_inline_at(addr: u64, func: &FuncRecord) -> Vec<InlineInfo>`: Return all inline frames active at `addr`, innermost-first.

4. **Handle large `.sym` files efficiently.**
   - xul.sym can be hundreds of megabytes. Parse into owned data structures (no borrowing from the input to avoid lifetime complexity).
   - Pre-sort `functions` and `publics` by address during parsing (they should already be sorted in the file, but verify/re-sort).
   - Consider a name → index hashmap for `find_function_by_name` to avoid linear scan.

### Acceptance Criteria

- Parse a real `ntdll.sym` or `xul.sym` downloaded in Phase 2. No panics, no parsing errors.
- `module` record correctly extracted (os, arch, debug_id, name).
- `find_function_by_name("NtCreateFile")` returns the correct function (for ntdll).
- `find_function_at_address(addr)` correctly finds the enclosing function for an address in the middle of a function.
- `resolve_address` falls back to PUBLIC symbols for addresses not in any FUNC range.
- Source line lookup returns the correct file and line.

### Tests

- Unit test: parse a minimal hand-crafted `.sym` file with all record types.
- Unit test: binary search correctness — address at start, middle, end of function, between functions, before first function, after last function.
- Unit test: fuzzy name search returns multiple matches.
- Unit test: inline record parsing with multiple ranges.
- Performance test: parse a large `.sym` file (> 100 MB) in under 10 seconds (rough target).

---

## Phase 4: PE Binary Parsing

**Goal:** Extract code bytes from a Windows PE file at a given RVA.

We start with PE because Windows modules have the best binary availability from symbol servers.

### Tasks

1. **Implement PE handling** in `src/binary/pe.rs`.
   - `load_pe(path: &Path) -> Result<PeFile>`: Parse the PE file using `goblin::pe::PE::parse`.
   - `PeFile` struct wrapping the parsed data and raw bytes.

2. **Implement RVA-to-file-offset conversion.**
   - `rva_to_offset(rva: u64) -> Option<u64>`: Walk the section table, find the section where `section.virtual_address <= rva < section.virtual_address + section.virtual_size`, compute `file_offset = rva - section.virtual_address + section.pointer_to_raw_data`.

3. **Implement code extraction.**
   - `extract_code(rva: u64, size: u64) -> Result<&[u8]>`: Convert RVA to file offset, return the byte slice. Handle the edge case where the range spans section boundaries (rare but possible — return an error, don't try to stitch).

4. **Implement architecture detection from PE headers.**
   - Read `IMAGE_FILE_HEADER.Machine`: `0x14c` = x86, `0x8664` = x86-64, `0xaa64` = ARM64, `0x1c0`/`0x1c4` = ARM32.
   - Map to a `CpuArch` enum shared across the codebase.

5. **Implement symbol table reading from PE exports.**
   - Read the export table to get exported function names and RVAs.
   - This is a fallback for when no `.sym` file is available — PE exports are much sparser than Breakpad symbols.

6. **Implement import table reading.**
   - Read the import directory to map IAT slots to imported function names.
   - Store as a map: `rva -> (dll_name, function_name)`.
   - This will be used later in Phase 8 to resolve `call [rip+offset]` instructions that go through the IAT.

7. **Define the common binary trait** in `src/binary/mod.rs`.
   ```rust
   pub enum CpuArch { X86, X86_64, Arm, Arm64 }

   pub trait BinaryFile {
       fn arch(&self) -> CpuArch;
       fn extract_code(&self, rva: u64, size: u64) -> Result<Vec<u8>>;
       fn resolve_import(&self, rva: u64) -> Option<(String, String)>;
       fn exports(&self) -> &[(u64, String)]; // (rva, name)
   }
   ```

### Dependencies to add

```toml
goblin = "0.9"
```

### Acceptance Criteria

- Load a real `ntdll.dll` from the cache. No parsing errors.
- `extract_code` for a known function RVA (from the `.sym` file) returns non-zero bytes that look like code (starts with common prologue bytes like `0x48 0x89` for x86-64).
- Architecture detection returns `X86_64` for a 64-bit DLL, `X86` for a 32-bit DLL.
- Export table reading finds expected exported functions (e.g., `NtCreateFile` in ntdll.dll).
- Import table reading finds expected imports.

### Tests

- Unit test: RVA-to-offset conversion with a crafted section table.
- Unit test: architecture detection for each machine type.
- Integration test: load a real PE file, extract a known function's code, verify first bytes match expected prologue.

---

## Phase 5: Disassembly Engine

**Goal:** Raw disassembly of code bytes for any supported architecture.

### Tasks

1. **Implement the Capstone wrapper** in `src/disasm/engine.rs`.
   - `Disassembler::new(arch: CpuArch, syntax: Syntax) -> Result<Self>`: Create a Capstone instance with the right architecture and mode.
     - `X86` → `CS_ARCH_X86, CS_MODE_32`
     - `X86_64` → `CS_ARCH_X86, CS_MODE_64`
     - `Arm` → `CS_ARCH_ARM, CS_MODE_ARM` (also handle Thumb mode: `CS_MODE_THUMB`)
     - `Arm64` → `CS_ARCH_ARM64, CS_MODE_ARM`
   - `Syntax::Intel` → `CS_OPT_SYNTAX_INTEL`, `Syntax::Att` → `CS_OPT_SYNTAX_ATT`.
   - Enable detail mode (`CS_OPT_DETAIL`) for instruction analysis (needed later for call target extraction).

2. **Define the instruction model.**
   ```rust
   pub struct Instruction {
       pub address: u64,       // RVA
       pub size: u8,
       pub bytes: Vec<u8>,
       pub mnemonic: String,
       pub operands: String,
   }
   ```

3. **Implement disassembly.**
   - `disassemble(code: &[u8], base_addr: u64, max_instructions: usize) -> Result<Vec<Instruction>>`: Disassemble the code bytes starting at `base_addr`. Stop at `max_instructions` or end of code.
   - Handle Capstone errors (invalid instruction sequences): insert a pseudo-instruction `db 0xXX` for bytes that can't be decoded, then try to resume disassembly at the next byte.

4. **Implement call target extraction.**
   - For x86/x86-64: detect `call` and `jmp` instructions. For direct calls (`E8`-relative, `FF /2`-absolute), compute the absolute target address. For RIP-relative calls, compute `rip + displacement`.
   - For ARM/AArch64: detect `bl`, `b`, `blr` instructions. Extract target address from immediate operand.
   - Use Capstone's detail mode to get instruction groups and operand details.
   - Add a `call_target: Option<u64>` field to `Instruction`.
   - Add an `is_indirect_call: bool` field for indirect calls whose target can't be statically determined.

### Dependencies to add

```toml
capstone = "0.13"
```

### Acceptance Criteria

- Disassemble a known byte sequence (e.g., `\x55\x48\x89\xe5\x48\x83\xec\x10` = typical x86-64 prologue) and get correct mnemonics (`push rbp; mov rbp, rsp; sub rsp, 0x10`).
- Call target extraction: for a `call <relative>` instruction, the computed target address is correct.
- AT&T syntax produces `pushq %rbp` instead of `push rbp`.
- ARM disassembly works for a known ARM byte sequence.
- Invalid bytes produce `db` pseudo-instructions without panicking.
- `max_instructions` limit is respected.

### Tests

- Unit test: known x86-64 byte sequences → expected disassembly.
- Unit test: known ARM64 byte sequences → expected disassembly.
- Unit test: call target computation for various call encodings (direct near, direct far, RIP-relative).
- Unit test: invalid byte handling (doesn't panic, produces `db`).
- Unit test: Intel vs AT&T syntax output.

---

## Phase 6: The `disasm` Command — MVP

**Goal:** First end-to-end working flow. `symdis disasm` fetches a module, finds a function, and prints raw disassembly. No annotations yet.

This is the **minimum viable product** — the tool is usable from this point forward.

### Tasks

1. **Implement the symbol resolver** in `src/symbols/resolver.rs`.
   - `resolve_module(debug_file, debug_id, code_file?, code_id?) -> ModuleResolution`:
     1. Fetch the `.sym` file (via Phase 2 fetch orchestrator).
     2. Parse it (via Phase 3 parser).
     3. Fetch the binary (via Phase 2 fetch orchestrator).
     4. Parse it (via Phase 4 PE parser).
     5. Return a `ModuleResolution` containing optional `SymFile` and optional `BinaryFile`.
   - Run sym and binary fetches concurrently with `tokio::join!`.

2. **Implement function targeting.**
   - `find_target(resolution: &ModuleResolution, target: Target) -> Result<FunctionTarget>`:
     - `Target::Function(name)`: Look up in `SymFile` first, then fall back to binary exports.
     - `Target::Offset(addr)`: Look up in `SymFile` first, then fall back to nearest binary export.
   - `FunctionTarget` contains: name, start address (RVA), size.
   - For PUBLIC-only symbols (no size info), estimate size as the distance to the next symbol (capped at a reasonable maximum like 64KB).

3. **Wire up the `disasm` command** in `src/commands/disasm.rs`.
   - Parse arguments.
   - Call `resolve_module`.
   - Call `find_target`.
   - If binary is available: extract code bytes, disassemble, print in text format.
   - If binary is unavailable but sym is: print function info (name, address, size) with a message that disassembly is not available.
   - If nothing is available: print error with details.

4. **Implement basic text output** in `src/output/text.rs`.
   - Print the header block (module, function, arch, data source).
   - Print each instruction: `0xADDRESS:  mnemonic  operands`.
   - No annotations yet — just raw disassembly.

### Acceptance Criteria

The following works end-to-end:
```bash
# With a real debug ID for a Windows system DLL
symdis disasm --debug-file ntdll.pdb --debug-id <real_id> --function NtCreateFile
```
Output is a working disassembly listing of the `NtCreateFile` function.

Also works:
```bash
symdis disasm --debug-file ntdll.pdb --debug-id <real_id> --offset 0x<some_offset>
```

And the sym-only fallback:
```bash
symdis disasm --debug-file xul.pdb --debug-id <real_id> --function "some::Function"
# If binary can't be fetched, shows function metadata without disassembly
```

### Tests

- Integration test: mock HTTP server serves a known `.sym` file and a known PE binary. Run `disasm --function`, verify output contains expected instructions.
- Integration test: same but only `.sym` available (no binary). Verify graceful fallback.
- Integration test: `--offset` targeting works.

---

## Phase 7: Annotation Engine

**Goal:** Disassembly output is annotated with source lines, call targets, and highlight markers.

### Tasks

1. **Implement source line annotation** in `src/disasm/annotate.rs`.
   - `annotate_source_lines(instructions: &mut [AnnotatedInstruction], sym: &SymFile, func: &FuncRecord)`:
     - For each instruction, look up the source line in the function's line records.
     - Track "current source line" — only emit a new source annotation when the line changes.
   - Add `source_file: Option<String>` and `source_line: Option<u32>` to the instruction model.

2. **Implement call target resolution.**
   - `annotate_call_targets(instructions: &mut [AnnotatedInstruction], sym: &SymFile, binary: Option<&BinaryFile>)`:
     - For each instruction with `call_target: Some(addr)`:
       - Try `sym.resolve_address(addr)` to get the target function name.
       - If that fails and binary is available, try `binary.resolve_import(addr)` for IAT/PLT calls.
       - If resolved, set `call_target_name: Some(name)`.
     - For indirect calls, set `call_target_name: Some("[indirect]")`.

3. **Implement inline function annotation.**
   - `annotate_inlines(instructions: &mut [AnnotatedInstruction], sym: &SymFile, func: &FuncRecord)`:
     - For each instruction, check which inline frames are active at that address.
     - Track inline depth transitions — emit `[inline]` markers when entering and `[end inline]` when leaving.
   - Add `inline_function: Option<String>` and `inline_depth: u32` to the instruction model.

4. **Implement highlight offset.**
   - `annotate_highlight(instructions: &mut [AnnotatedInstruction], offset: u64)`:
     - Find the instruction at or nearest to the given offset, set `highlighted: true`.

5. **Extend the text formatter** to render annotations.
   - Source line comments: `; path/to/file.cpp:123` on a line before the instruction group.
   - Call annotations: `; TargetFunction` appended after the operands.
   - Inline markers: `; [inline] FuncName (file.cpp:42)`.
   - Highlight marker: `==>` prefix on the highlighted instruction.

6. **Wire annotations into the `disasm` command.**
   After disassembly, run the annotation pipeline (source lines → call targets → inlines → highlight) before formatting.

### Acceptance Criteria

Disassembly of a function from a module where both binary and `.sym` are available shows:
- Source file/line annotations that change throughout the function.
- Call instructions annotated with target function names.
- Inline function boundary markers.
- A highlighted instruction when `--highlight-offset` is given.

### Tests

- Unit test for source line annotation: craft a `FuncRecord` with known line records, verify annotations match.
- Unit test for call target resolution: instruction at known address with known target, verify name resolution.
- Unit test for inline annotation: multiple inline depths, verify entry/exit markers.
- Integration test: full annotated disassembly of a real function, spot-check annotations.

---

## Phase 8: JSON Output

**Goal:** All commands can produce structured JSON output.

### Tasks

1. **Define JSON output types** in `src/output/json.rs`.
   - `DisasmOutput`: the full JSON structure from spec section 4.1.
   - `LookupOutput`: the JSON structure from spec section 4.2.
   - `InfoOutput`: the JSON structure from spec section 4.3.
   - `ErrorOutput`: the error JSON structure from spec section 11.
   - All types derive `Serialize`.

2. **Implement JSON formatter.**
   - `format_disasm_json(result: &DisasmResult) -> String`: Serialize to pretty-printed JSON.
   - Include `"source"` field (`"binary+sym"`, `"binary"`, `"sym"`).
   - Include `"warnings"` array for non-fatal issues.

3. **Implement JSON error output.**
   - When an error occurs and `--format json` is active, output the error as a JSON object with `"error"` and optional `"partial_result"` instead of printing to stderr.
   - Define error codes: `MODULE_NOT_FOUND`, `BINARY_NOT_FOUND`, `SYM_NOT_FOUND`, `FUNCTION_NOT_FOUND`, `OFFSET_OUT_OF_RANGE`, `NETWORK_ERROR`, `UNSUPPORTED_ARCH`, `PARSE_ERROR`.

4. **Wire `--format json` through all commands.**
   Check the format flag in each command and dispatch to the appropriate formatter.

### Acceptance Criteria

- `symdis disasm ... --format json` produces valid JSON matching the spec's schema.
- JSON output includes all instruction fields (address, bytes, mnemonic, operands, source_file, source_line, highlighted, call_target, inline_function).
- Error cases produce JSON errors instead of stderr text when `--format json`.
- `jq` can parse and query the output without errors.

### Tests

- Unit test: serialize a crafted `DisasmOutput`, parse it back, verify round-trip.
- Unit test: error JSON includes partial_result when available.
- Integration test: `--format json` output can be parsed by `serde_json::from_str`.

---

## Phase 9: Remaining Commands (`lookup`, `info`)

**Goal:** The `lookup` and `info` commands are fully functional.

### Tasks

1. **Implement the `lookup` command** in `src/commands/lookup.rs`.
   - Fetch only the `.sym` file (no binary needed).
   - If `--offset`: resolve via `sym.resolve_address()`, return function name, offset within function, source location, inline frames.
   - If `--function`: look up function, return its address, size, source file.
   - Text and JSON formatters.

2. **Implement the `info` command** in `src/commands/info.rs`.
   - Fetch the `.sym` file (HEAD request first to check existence without downloading, or just download and examine).
   - Check binary availability (HEAD request or cache check).
   - Parse `.sym` file to count functions, publics.
   - Report: module name, debug file/id, code file/id, OS, arch, sym file status + size, binary status + size, function count, public symbol count.
   - Text and JSON formatters.

3. **Implement the `--fuzzy` flag for `disasm` and `lookup`.**
   - When `--function` is given with `--fuzzy`, use `find_function_by_name_fuzzy`.
   - If exactly one match, proceed normally.
   - If multiple matches, list them and exit (with a non-zero exit code).
   - In JSON mode, the error includes a `"matches"` array.

### Acceptance Criteria

- `symdis lookup --debug-file ntdll.pdb --debug-id <id> --offset 0x<addr>` prints the function name and source location.
- `symdis info --debug-file ntdll.pdb --debug-id <id>` prints module metadata.
- `--fuzzy` with an ambiguous pattern lists matches.

### Tests

- Integration test: `lookup` with a known offset returns the expected function.
- Integration test: `info` shows correct metadata.
- Unit test: fuzzy matching returns correct candidates.

---

## Phase 10: ELF Support & debuginfod

**Goal:** Linux modules can be fetched and disassembled.

### Tasks

1. **Implement Debug ID ↔ Build ID conversion** in `src/symbols/id_convert.rs`.
   - `debug_id_to_build_id(debug_id: &str) -> Result<String>`:
     - Take the first 32 hex chars (the GUID portion, ignoring the final age char).
     - Reverse the byte-swapping: re-swap Data1 (4 bytes), Data2 (2 bytes), Data3 (2 bytes). Data4 unchanged.
     - Return as lowercase hex string.
   - `build_id_to_debug_id(build_id: &str) -> String`: the inverse.
   - Also handle the case where the build ID is longer than 16 bytes (the remainder is appended as-is after the converted prefix).

2. **Implement the debuginfod client** in `src/fetch/debuginfod.rs`.
   - `fetch_executable(build_id: &str) -> FetchResult`: `GET <server>/buildid/<build_id>/executable`.
   - `fetch_debuginfo(build_id: &str) -> FetchResult`: `GET <server>/buildid/<build_id>/debuginfo`.
   - Support multiple servers (try each in order).
   - Respect the `DEBUGINFOD_URLS` environment variable.

3. **Implement ELF handling** in `src/binary/elf.rs`.
   - `load_elf(path: &Path) -> Result<ElfFile>`: Parse with `goblin::elf::Elf::parse`.
   - RVA-to-file-offset conversion using program headers (`PT_LOAD`).
   - Architecture detection from `e_machine`: `EM_386` → X86, `EM_X86_64` → X86_64, `EM_ARM` → Arm, `EM_AARCH64` → Arm64.
   - Code extraction.
   - Import/export resolution from `.dynsym`, `.symtab`, and `.rela.plt` / `.got.plt` sections.
   - Implement the `BinaryFile` trait.

4. **Integrate debuginfod into the fetch orchestrator.**
   - After Tecken, before giving up on a binary, check if the module is Linux (from the `.sym` MODULE record's OS field).
   - If Linux, convert debug ID to build ID and try debuginfod.

5. **Add the `--os` hint flag.**
   - When no `.sym` file is available and the OS can't be auto-detected, allow the user to specify `--os linux` so the tool knows to try debuginfod and interpret the binary as ELF.

### Acceptance Criteria

- Debug ID → Build ID conversion matches known test vectors (from Appendix C of the spec).
- `symdis disasm --debug-file libxul.so --debug-id <linux_id> --function <func>` works when the binary is available via debuginfod or Tecken.
- ELF code extraction produces valid bytes for disassembly.
- ARM and AArch64 ELF binaries are handled correctly.

### Tests

- Unit test: Debug ID ↔ Build ID round-trip for known examples.
- Unit test: ELF RVA-to-offset conversion.
- Unit test: ELF architecture detection.
- Integration test with mock debuginfod server.

---

## Phase 11: Mach-O Support

**Goal:** macOS modules can be parsed (binary availability may be limited, but parsing works when the binary is available).

### Tasks

1. **Implement Mach-O handling** in `src/binary/macho.rs`.
   - `load_macho(path: &Path) -> Result<MachOFile>`: Parse with `goblin::mach::Mach::parse`.
   - Handle both single-arch and universal (fat) binaries. For fat binaries, select the slice matching the target architecture.
   - Architecture detection from `cputype`: `CPU_TYPE_X86` → X86, `CPU_TYPE_X86_64` → X86_64, `CPU_TYPE_ARM` → Arm, `CPU_TYPE_ARM64` → Arm64.
   - RVA-to-file-offset: use `__TEXT` segment's `vmaddr` and `fileoff`. For a given RVA, find the section containing it, compute `file_offset = rva - section.addr + section.offset`.
   - Code extraction.
   - Export resolution from the export trie or `LC_SYMTAB` symbol table.
   - Import resolution from `LC_DYSYMTAB` and the lazy/non-lazy binding info.
   - Implement the `BinaryFile` trait.

2. **Implement binary format auto-detection** in `src/binary/mod.rs`.
   - `load_binary(path: &Path) -> Result<Box<dyn BinaryFile>>`:
     - Read the first 4 bytes (magic number).
     - `MZ` → PE, `\x7fELF` → ELF, `\xfe\xed\xfa\xce/\xcf` or `\xca\xfe\xba\xbe` → Mach-O.
     - Dispatch to the appropriate loader.

3. **Integrate Mach-O into the resolver.**
   - When a fetched binary is Mach-O format, use the Mach-O loader.

### Acceptance Criteria

- Load a real macOS Mach-O binary (e.g., from a local Firefox build), extract code, disassemble correctly.
- Fat binaries: the correct architecture slice is selected.
- Auto-detection correctly identifies PE, ELF, and Mach-O files.

### Tests

- Unit test: Mach-O architecture detection.
- Unit test: Mach-O RVA-to-offset conversion.
- Unit test: auto-detection with known magic bytes.
- Integration test: disassemble a Mach-O binary's function.

---

## Phase 12: `frames` Command & Crash Report Parsing

**Goal:** Parse processed crash report JSON files and batch-disassemble stack frames.

### Tasks

1. **Implement crash report parser** in `src/crash_report.rs`.
   - Define types for the rust-minidump / Socorro JSON format:
     ```rust
     pub struct CrashReport {
         pub crash_info: Option<CrashInfo>,
         pub crashing_thread: Option<usize>,
         pub threads: Vec<Thread>,
         pub modules: Vec<Module>,
     }
     ```
   - Parse with `serde_json`. Be tolerant of missing fields (everything optional, use `#[serde(default)]`).
   - `get_thread(spec: &str) -> &Thread`: resolve `"crashing"` to `threads[crashing_thread]`, or parse as index.
   - `get_module_for_frame(frame: &Frame) -> Option<&Module>`: Match frame's module name to modules list.

2. **Implement frame range parsing.**
   - Parse `--frames` argument: `"all"`, `"5"`, `"0-9"`, `"3,5,7"`.

3. **Implement the `frames` command** in `src/commands/frames.rs`.
   - Read crash report from file path.
   - Extract requested thread and frames.
   - For each frame:
     1. Find the module in the modules list.
     2. Call the same resolve → disassemble → annotate pipeline as `disasm`.
     3. Use `module_offset` as the `--offset` and also as `--highlight-offset`.
   - Deduplicate module fetches: if multiple frames reference the same module, fetch it once.
   - Text output: print each frame's disassembly separated by a header line.
   - JSON output: array of per-frame results.

4. **Handle frames with missing modules.**
   - If a frame has no module (address not in any loaded module), skip it with a warning.
   - If a frame's module can't be fetched, include a partial result.

### Acceptance Criteria

- Given a real processed crash report JSON, `symdis frames --crash-report crash.json --frames 0-3` produces disassembly for the top 4 frames of the crashing thread.
- Frames with different modules trigger separate fetches.
- Frames in the same module reuse the cached data.
- `--format json` produces an array of results.

### Tests

- Unit test: crash report JSON parsing with a fixture file.
- Unit test: frame range parsing (`"all"`, `"5"`, `"0-9"`, `"3,5,7"`).
- Integration test: `frames` command with a mock crash report and mock HTTP server.

---

## Phase 13: C++ / Rust Demangling

**Goal:** Mangled symbol names are demangled for readability.

### Tasks

1. **Add demangling to symbol resolution.**
   - In `SymFile` parsing: function names in `.sym` files are usually already demangled (Breakpad's `dump_syms` demangles). But PUBLIC records may still be mangled. Apply demangling to PUBLIC names.
   - In binary export/symbol table reading: names are typically mangled. Demangle when displaying.

2. **Implement demangling dispatch.**
   - Try `cpp_demangle::Symbol::new(name)` for C++ (Itanium ABI and MSVC mangling).
   - Try `rustc_demangle::demangle(name)` for Rust symbols.
   - If neither succeeds, use the original name.

3. **Add `--no-demangle` flag** to skip demangling (useful for searching by mangled name).

### Dependencies to add

```toml
cpp_demangle = "0.4"
rustc-demangle = "0.1"
```

### Acceptance Criteria

- `_ZN7mozilla3dom7Element12SetAttributeERKNS_6nsAStrES4_R10ByRefErrorResult` is displayed as `mozilla::dom::Element::SetAttribute(...)`.
- Rust symbols like `_RNvNtC7symdis5fetch6tecken` are demangled.
- `--no-demangle` shows the raw mangled name.

### Tests

- Unit test: known C++ mangled names → expected demangled output.
- Unit test: known Rust mangled names → expected demangled output.
- Unit test: unmangled names pass through unchanged.

---

## Phase 14: Configuration File & Environment Variables

**Goal:** Full configuration system per the spec.

### Tasks

1. **Implement TOML config file parsing** in `src/config.rs`.
   - Locate the config file per the spec's platform paths.
   - Parse with `toml` crate.
   - Merge with defaults: config file overrides defaults, env vars override config, CLI flags override everything.

2. **Implement environment variable reading.**
   - `SYMDIS_CACHE_DIR`, `SYMDIS_CONFIG`, `SYMDIS_SYMBOL_SERVERS`, `DEBUGINFOD_URLS`.

3. **Wire configuration through all subsystems.**
   - Cache directory, symbol server URLs, debuginfod URLs, timeouts, syntax, max instructions, format, etc.

### Dependencies to add

```toml
toml = "0.8"
```

### Acceptance Criteria

- A config file at the expected path is read and applied.
- `SYMDIS_SYMBOL_SERVERS=https://custom.server/` overrides the default servers.
- CLI `--cache-dir /tmp/test` overrides everything else.
- `symdis disasm ... --verbose` shows which config values are in effect.

### Tests

- Unit test: config merging precedence (default < file < env < CLI).
- Unit test: TOML parsing with all fields, partial fields, empty file.

---

## Phase 15: Robustness, Logging & Polish

**Goal:** Production-quality error handling, logging, progress reporting.

### Tasks

1. **Add `--verbose` / `-v` flag.**
   - `-v`: Log info-level messages (which servers are being queried, cache hits/misses).
   - `-vv`: Log debug-level messages (HTTP request/response details, parsing progress).
   - Use the `tracing` crate for structured logging.
   - Log to stderr so stdout is clean for tool output (important for AI agent consumption).

2. **Add progress indication.**
   - When downloading large files, print progress to stderr: `Downloading xul.sym (43 MB)...`.
   - Disable progress output when stderr is not a terminal (piped output).

3. **Improve error messages.**
   - Every error should include enough context for the user to understand what went wrong and what to try next.
   - For `FUNCTION_NOT_FOUND`: suggest similar function names (Levenshtein distance or prefix matching).
   - For `MODULE_NOT_FOUND`: suggest checking the debug-file and debug-id values.

4. **Handle edge cases.**
   - Very large functions (> 100KB code): respect `--max-instructions`.
   - Empty functions (size 0 in `.sym` file): report gracefully.
   - Corrupted downloads: detect (e.g., HTML error page instead of binary), delete from cache, retry once.
   - Interrupted downloads (Ctrl+C): clean up temp files.
   - Concurrent access: cache operations are atomic, so concurrent `symdis` invocations sharing a cache should be safe.

5. **Add `--version` flag.**
   Print version, build info (git commit, target triple).

6. **Add `--offline` flag.**
   Skip all network requests, only use cached data. Useful when the user has pre-fetched everything.

### Dependencies to add

```toml
tracing = "0.1"
tracing-subscriber = "0.3"
```

### Acceptance Criteria

- `symdis --version` prints version and build info.
- `-v` output shows cache hit/miss and server queries.
- A fetch failure shows a clear error with what was tried.
- `--offline` works with pre-cached modules.
- `--max-instructions` truncates output with a message.
- Ctrl+C during download doesn't leave corrupt files in cache.

---

## Phase 16: Integration Testing with Real Data

**Goal:** Verify the tool works end-to-end with real Mozilla crash data.

### Tasks

1. **Create an integration test suite using real crash reports.**
   - Pick 5-10 representative crash reports from Crash Stats covering:
     - Windows x86-64 (most common).
     - Windows x86 (32-bit Firefox).
     - Linux x86-64.
     - macOS x86-64.
     - macOS AArch64 (Apple Silicon).
     - Android AArch64.
   - For each, save the processed crash report JSON as a test fixture.

2. **Write end-to-end tests.**
   - For each crash report: run `symdis frames --crash-report <fixture> --frames 0 --format json`.
   - Verify the output is valid JSON with the expected structure.
   - Verify that at least the top frame produces disassembly (for Windows) or symbol info (for other platforms).
   - These tests require network access; gate behind a feature flag or env var (`SYMDIS_INTEGRATION_TESTS=1`).

3. **Write performance benchmarks.**
   - Benchmark `.sym` file parsing for a large file (xul.sym).
   - Benchmark disassembly of a large function.
   - Benchmark end-to-end `disasm` command (with warm cache).
   - Use the `criterion` crate.

4. **Test `_NT_SYMBOL_PATH` integration on Windows.**
   - Verify that if a PE file exists in the WinDbg symbol cache, `symdis` finds it without re-downloading.

### Acceptance Criteria

- All integration tests pass (with network access).
- Performance: `disasm` of a typical function completes in under 2 seconds (warm cache).
- Performance: parsing xul.sym (400+ MB) completes in under 15 seconds.

---

## Phase Summary

| Phase | Description | Key Deliverable | Depends On |
|---|---|---|---|
| 0 | Project bootstrap | CLI skeleton compiles | — |
| 1 | Cache infrastructure | Files stored/retrieved from cache | 0 |
| 2 | HTTP fetching | Download from Tecken + Microsoft | 1 |
| 3 | Breakpad .sym parser | Queryable symbol data | 0 |
| 4 | PE binary parsing | Code bytes extracted from DLLs | 0 |
| 5 | Disassembly engine | Raw disassembly of byte arrays | 0 |
| **6** | **`disasm` MVP** | **First working end-to-end flow** | **2, 3, 4, 5** |
| 7 | Annotation engine | Source lines, call targets, highlights | 3, 5, 6 |
| 8 | JSON output | `--format json` for all commands | 6, 7 |
| 9 | `lookup` + `info` commands | All query commands working | 3, 8 |
| 10 | ELF + debuginfod | Linux module support | 6 |
| 11 | Mach-O support | macOS module support | 6 |
| 12 | `frames` command | Batch crash report processing | 6, 8 |
| 13 | Demangling | Readable C++/Rust names | 6 |
| 14 | Configuration file | Persistent settings | 1, 2 |
| 15 | Robustness & polish | Production-ready error handling | All |
| 16 | Integration testing | Verified with real data | All |

### Dependency Graph

```
Phase 0 ──┬──> Phase 1 ──> Phase 2 ──┐
           ├──> Phase 3 ──────────────┤
           ├──> Phase 4 ──────────────┤
           └──> Phase 5 ──────────────┤
                                      v
                               Phase 6 (MVP)
                                  │
                    ┌─────────────┼─────────────┐
                    v             v              v
                Phase 7      Phase 10       Phase 12
                    │         Phase 11       Phase 13
                    v
                Phase 8
                    │
                    v
                Phase 9
                    │
                    v
               Phase 14
                    │
                    v
               Phase 15
                    │
                    v
               Phase 16
```

Phases 10, 11, 12, 13 are independent of each other and can be developed in parallel after Phase 6.
