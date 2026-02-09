# symdis — Specification

**Symbolic Disassembler for Mozilla Crash Report Analysis**

Version: 0.1 (Draft)
Date: 2026-02-06

---

## 1. Overview

`symdis` is a CLI tool designed for use by AI agents analyzing Mozilla crash reports. Given a module identifier and either a function name or an offset, it returns annotated disassembly of the corresponding function. It fetches binaries and symbol information from Mozilla's and Microsoft's symbol servers, caching downloads locally.

### Problem Statement

When an AI agent analyzes a Mozilla crash report (from Socorro/Crash Stats), it sees symbolicated stack traces with function names, offsets, and module information. To understand the root cause of a crash, the agent often needs to inspect the actual machine code that was executing — what instructions led to the faulting address, what was being called, how arguments were being set up. Today, there is no single tool that bridges the gap between a crash report's stack frame metadata and the disassembled machine code of the relevant functions.

### Design Principles

- **AI-agent-first**: Output formats, error messages, and interaction patterns are optimized for consumption by language models, not human developers.
- **Stateless invocations**: Each command is self-contained. No persistent server process or session state.
- **Graceful degradation**: Returns whatever information is available, even if incomplete (e.g., symbol info without disassembly when binaries are unavailable).
- **Minimal configuration**: Works out of the box with sensible defaults; respects existing system symbol caches.

---

## 2. Goals and Non-Goals

### Goals

- Disassemble functions from any module present in a Firefox crash report, across all platforms Firefox runs on (Windows, Linux, macOS, Android).
- Resolve symbols by function name or by RVA (relative virtual address) / module offset.
- Fetch the actual binary modules and symbol files from Mozilla's Tecken symbol server, Microsoft's public symbol server, and Linux debuginfod servers.
- Annotate disassembly output with source file/line information when available.
- Annotate call instructions with resolved target symbol names when possible.
- Cache all downloaded artifacts to avoid redundant network traffic.
- Produce both human-readable and machine-parseable (JSON) output.
- Support x86, x86-64, ARM32, and AArch64 architectures.

### Non-Goals

- Processing raw minidump files (use `minidump-stackwalk` for that).
- Full decompilation to C/C++ (use Ghidra or IDA for that).
- Stack unwinding or crash reprocessing.
- Uploading symbols.
- Acting as a symbol server or proxy.
- Debugging live processes.

---

## 3. User Interaction Model

### Typical Workflow

An AI agent analyzing a crash report follows this workflow:

1. **Obtain crash report data.** The agent has a processed crash report (JSON) or a Crash Stats URL. The report contains a modules list and stack traces with frames referencing module names, debug IDs, offsets, and (possibly) function names.

2. **Identify frames of interest.** The agent picks stack frames to investigate — typically the crashing frame (frame 0 of the crashing thread) and nearby callers. The agent is responsible for selecting which frames are worth disassembling.

3. **Request disassembly.** For each frame of interest, the agent calls `symdis disasm` with the module's debug file, debug ID, and either the function name or the module offset.

4. **Analyze the output.** The agent reads the annotated disassembly to understand control flow, identify the faulting instruction, trace argument setup, etc.

5. **Iterate.** The agent may request disassembly of additional functions (callees, callers, related code paths).

### Example Session

```bash
# Disassemble a function by name
$ symdis disasm \
    --debug-file xul.pdb \
    --debug-id 44E4EC8C2F41492B9369D6B9A059577C2 \
    --function "mozilla::dom::Element::SetAttribute"

# Disassemble the function containing a specific offset
$ symdis disasm \
    --debug-file xul.pdb \
    --debug-id 44E4EC8C2F41492B9369D6B9A059577C2 \
    --offset 0x1a3f00

# Same, with JSON output
$ symdis disasm \
    --debug-file xul.pdb \
    --debug-id 44E4EC8C2F41492B9369D6B9A059577C2 \
    --offset 0x1a3f00 \
    --format json

# Look up what symbol is at a given offset
$ symdis lookup \
    --debug-file xul.pdb \
    --debug-id 44E4EC8C2F41492B9369D6B9A059577C2 \
    --offset 0x1a3f00

# Show module metadata
$ symdis info \
    --debug-file xul.pdb \
    --debug-id 44E4EC8C2F41492B9369D6B9A059577C2

# Pre-fetch symbols and binary for a module
$ symdis fetch \
    --debug-file xul.pdb \
    --debug-id 44E4EC8C2F41492B9369D6B9A059577C2
```

---

## 4. Commands

### 4.1. `symdis disasm`

**Purpose:** Disassemble a function from a module.

**Required parameters:**

| Parameter | Description |
|---|---|
| `--debug-file <NAME>` | Debug file name (e.g., `xul.pdb`, `libxul.so`, `XUL`) |
| `--debug-id <ID>` | Debug identifier (33-character hex string, e.g., `44E4EC8C2F41492B9369D6B9A059577C2`) |

**Target (one required):**

| Parameter | Description |
|---|---|
| `--function <NAME>` | Function name (exact match, or substring match with `--fuzzy`) |
| `--offset <ADDR>` | RVA / module offset (hex, with or without `0x` prefix). The tool finds the function containing this address. |

**Options:**

| Option | Default | Description |
|---|---|---|
| `--format <FMT>` | `text` | Output format: `text` or `json` |
| `--syntax <SYN>` | `intel` | Disassembly syntax: `intel` or `att` |
| `--context <N>` | (none) | When using `--offset`, also show N bytes of disassembly before and after the target function (useful for seeing neighboring code). Not applicable with `--function`. |
| `--highlight-offset <ADDR>` | (none) | Mark a specific offset in the output (e.g., the return address from the crash report). Displayed as `==>` marker in text mode, `"highlighted": true` in JSON mode. |
| `--fuzzy` | off | Enable substring/fuzzy matching for `--function`. Lists matches if ambiguous. |
| `--max-instructions <N>` | 2000 | Safety limit on output size. |
| `--code-file <NAME>` | (none) | Code file name (e.g., `xul.dll`). Used as an alternative to debug-file when looking up the binary via code ID. |
| `--code-id <ID>` | (none) | Code identifier (e.g., `5CF2591C6859000`). Used as an alternative to debug-id when looking up the binary via TimeDateStamp+SizeOfImage. |

**Behavior:**

1. Resolve the module by downloading or locating the Breakpad `.sym` file and the native binary.
2. If `--function` is given: look up the function in the `.sym` file's FUNC records (or in the binary's symbol table). Retrieve its start address and size.
3. If `--offset` is given: find the FUNC record whose address range contains the offset, or, if no `.sym` file, scan the binary's symbol table.
4. Extract the code bytes from the binary at the function's address range.
5. Disassemble the code bytes using the appropriate architecture (determined from the `.sym` file's MODULE record or the binary's headers).
6. Annotate the disassembly with:
   - Source file and line numbers (from `.sym` line records or DWARF info).
   - Inlined function boundaries (from `.sym` INLINE records).
   - Resolved call targets: for `call` and `branch` instructions whose target is a known symbol, append the symbol name as a comment.
   - The highlight marker at `--highlight-offset` if provided.

**Output (text mode):**

```
; Module: xul.dll (xul.pdb / 44E4EC8C2F41492B9369D6B9A059577C2)
; Function: mozilla::dom::Element::SetAttribute (RVA: 0x1a3e80, size: 0x120)
; Source: dom/base/Element.cpp

; dom/base/Element.cpp:1234
0x001a3e80:  push    rbp
0x001a3e81:  mov     rbp, rsp
0x001a3e84:  sub     rsp, 0x40
; dom/base/Element.cpp:1235
0x001a3e88:  mov     qword ptr [rbp - 0x8], rcx
0x001a3e8c:  mov     qword ptr [rbp - 0x10], rdx
; [inline] mozilla::dom::Element::BeforeSetAttr (dom/base/Element.cpp:1180)
0x001a3e90:  lea     rcx, [rbp - 0x38]
0x001a3e94:  call    0x002b1200              ; nsAtom::ToString
    ...
==> 0x001a3f00:  call    0x001b2340              ; nsContentUtils::SetNodeTextContent
    ...
0x001a3f9f:  ret
```

**Output (JSON mode):**

```json
{
  "module": {
    "debug_file": "xul.pdb",
    "debug_id": "44E4EC8C2F41492B9369D6B9A059577C2",
    "code_file": "xul.dll",
    "arch": "x86_64",
    "os": "windows"
  },
  "function": {
    "name": "mozilla::dom::Element::SetAttribute",
    "address": "0x1a3e80",
    "size": "0x120",
    "source_file": "dom/base/Element.cpp"
  },
  "instructions": [
    {
      "address": "0x1a3e80",
      "bytes": "55",
      "mnemonic": "push",
      "operands": "rbp",
      "source_file": "dom/base/Element.cpp",
      "source_line": 1234,
      "highlighted": false,
      "inline_function": null
    },
    {
      "address": "0x1a3f00",
      "bytes": "e83b84000000",
      "mnemonic": "call",
      "operands": "0x001b2340",
      "call_target": "nsContentUtils::SetNodeTextContent",
      "source_file": "dom/base/Element.cpp",
      "source_line": 1242,
      "highlighted": true,
      "inline_function": null
    }
  ],
  "source": "binary+sym",
  "warnings": []
}
```

The `"source"` field indicates what data was available:
- `"binary+sym"`: Full disassembly with annotations (best case).
- `"binary"`: Disassembly without source/line annotations (no `.sym` file found).
- `"sym"`: Symbol information only, no disassembly (binary not found). The `instructions` array is empty, but the `function` object is populated.

### 4.2. `symdis lookup`

**Purpose:** Resolve a module offset to a symbol name and source location, or resolve a symbol name to an address.

**Parameters:** Same module identification as `disasm` (`--debug-file`, `--debug-id`), plus either `--offset` or `--function`.

**Output (text mode):**

```
0x001a3f00 => mozilla::dom::Element::SetAttribute + 0x80
  Source: dom/base/Element.cpp:1242
  Function range: 0x001a3e80 - 0x001a3fa0 (0x120 bytes)
```

**Output (JSON mode):**

```json
{
  "offset": "0x1a3f00",
  "function": "mozilla::dom::Element::SetAttribute",
  "function_offset": "0x80",
  "function_address": "0x1a3e80",
  "function_size": "0x120",
  "source_file": "dom/base/Element.cpp",
  "source_line": 1242,
  "inline_frames": [
    {
      "function": "mozilla::dom::Element::BeforeSetAttr",
      "source_file": "dom/base/Element.cpp",
      "source_line": 1180
    }
  ]
}
```

### 4.3. `symdis info`

**Purpose:** Show metadata about a module, and report whether the binary and `.sym` file are available (locally or on symbol servers).

**Parameters:** `--debug-file`, `--debug-id`. Optionally `--code-file`, `--code-id`.

**Output (text mode):**

```
Module: xul.dll
Debug file: xul.pdb
Debug ID: 44E4EC8C2F41492B9369D6B9A059577C2
Code file: xul.dll
Code ID: 5CF2591C6859000
OS: windows
Architecture: x86_64
Symbol file: cached (432 MB)
Binary file: cached (128 MB)
Functions: 284,301
PUBLIC symbols: 12,445
```

### 4.4. `symdis fetch`

**Purpose:** Pre-download the `.sym` file and binary for a module without producing disassembly. Useful for pre-warming the cache before a series of `disasm` calls.

**Parameters:** `--debug-file`, `--debug-id`. Optionally `--code-file`, `--code-id`.

**Behavior:** Downloads the `.sym` file and binary module (if available) to the local cache. Reports what was downloaded and what failed.

### 4.5. `symdis cache`

**Purpose:** Manage the local cache.

**Subcommands:**

| Subcommand | Description |
|---|---|
| `cache path` | Print the cache directory path. |
| `cache size` | Print the total size of cached files. |
| `cache clear` | Delete all cached files. |
| `cache clear --older-than <DAYS>` | Delete cached files older than N days. |
| `cache list --debug-file <NAME>` | List cached artifacts for a specific module. |

---

## 5. Symbol Resolution Pipeline

When `symdis` needs symbol information for a module, it follows this pipeline:

### 5.1. Local Cache Lookup

Check the local cache directory for previously downloaded files. The cache layout mirrors the symbol server directory structure:

```
<cache_root>/
  <debug_file>/<debug_id>/<debug_file>.sym      # Breakpad symbol file
  <code_file>/<code_id>/<code_file>              # Native binary
  <debug_file>/<debug_id>/<debug_file>           # PDB or dSYM (if applicable)
```

Negative results (confirmed 404s from servers) are cached as zero-byte `.miss` marker files with a configurable TTL (default: 24 hours) to avoid re-querying servers for known-missing artifacts.

### 5.2. Mozilla Symbol Server (Tecken)

**URL:** `https://symbols.mozilla.org/`

**Fetching `.sym` files:**
```
GET /<debug_file>/<debug_id>/<debug_file_stem>.sym
```
Example: `GET /xul.pdb/44E4EC8C2F41492B9369D6B9A059577C2/xul.sym`

Note: Responses are gzip-compressed (`Content-Encoding: gzip`). Follow 302 redirects to the actual storage backend.

**Fetching binaries (Windows):**

Tecken supports a code-file/code-id lookup path:
```
GET /<code_file>/<code_id>/<code_file>
```
Example: `GET /xul.dll/5CF2591C6859000/xul.dll`

Additionally, Tecken proxies requests to Microsoft's symbol server for modules it doesn't have.

### 5.3. Microsoft Symbol Server

**URL:** `https://msdl.microsoft.com/download/symbols`

**Fetching PDB files:**
```
GET /<pdb_name>/<GUID><Age>/<pdb_name>
```

**Fetching PE binaries:**
```
GET /<pe_name>/<TimeDateStamp><SizeOfImage>/<pe_name>
```

Also check for compressed variants (last extension character replaced with `_`, stored as CAB archives):
```
GET /<pe_name>/<TimeDateStamp><SizeOfImage>/<pe_name_compressed>
```
Example: `xul.dll` → `xul.dl_`, `ntdll.pdb` → `ntdll.pd_`

Decompress CAB files when saving to local cache.

### 5.4. Linux debuginfod Servers

**URLs:** Configurable; defaults to `https://debuginfod.elfutils.org/` (which federates to distribution servers).

**Fetching executables:**
```
GET /buildid/<build_id>/executable
```

**Fetching debug info:**
```
GET /buildid/<build_id>/debuginfo
```

The build ID is derived from the ELF `.note.gnu.build-id` section. For modules in crash reports, the debug ID (33 hex chars) needs to be converted back to a build ID by reversing the byte-swapping that Breakpad applies.

### 5.5. Identifier Conversion

Crash reports use Breakpad-format debug IDs, which differ from native identifiers by platform:

| Platform | Native ID | Breakpad debug_id conversion |
|---|---|---|
| Windows | GUID + Age (from PDB's RSDS record) | Direct: 32 hex digits of GUID + hex age = 33 chars |
| Linux | Build ID (20+ bytes from `.note.gnu.build-id`) | First 16 bytes: byte-swap first 3 GUID components, then append `0` as age |
| macOS | UUID (16 bytes from `LC_UUID`) | 32 hex digits of UUID + `0` as age |

`symdis` must perform these conversions when querying platform-specific symbol sources.

### 5.6. Resolution Priority

For each module, `symdis` attempts to acquire two artifacts:

1. **Symbol file** (for function names, boundaries, source lines, inlines):
   - Local cache → Mozilla Tecken (`.sym`) → (for Windows) Microsoft Symbol Server (PDB) → debuginfod (for Linux)

2. **Native binary** (for machine code):
   - Local cache → Mozilla Tecken (code-file/code-id) → Microsoft Symbol Server (PE) → debuginfod (for Linux executables)

Downloads are performed concurrently when both artifacts are needed.

---

## 6. Disassembly Engine

### 6.1. Architecture Detection

The target architecture is determined from:
1. The `.sym` file's `MODULE` record (e.g., `MODULE windows x86_64 ...`).
2. Or the binary's headers (PE machine type, ELF `e_machine`, Mach-O CPU type).

Supported architectures:

| Architecture | `.sym` identifier | Typical platforms |
|---|---|---|
| x86 (32-bit) | `x86` | Windows, Linux (legacy) |
| x86-64 | `x86_64` | Windows, Linux, macOS |
| ARM32 | `arm` | Android |
| AArch64 | `arm64` | Android, macOS (Apple Silicon), Windows (ARM) |

### 6.2. Code Extraction

The disassembly engine needs raw code bytes at the function's RVA:

- **PE files:** Read from the appropriate section (typically `.text`). Convert RVA to file offset using the section table.
- **ELF files:** Read from the executable segment (`PT_LOAD` with execute flag). Convert virtual address to file offset using program headers.
- **Mach-O files:** Read from the `__TEXT,__text` section. Convert virtual address to file offset using segment/section headers.

### 6.3. Disassembly

Use the Capstone disassembly engine (via Rust bindings) for multi-architecture support.

For each instruction, capture:
- Address (RVA)
- Raw bytes
- Mnemonic
- Operand string
- Instruction size

### 6.4. Annotation

After disassembly, annotate each instruction:

**Source lines:** Match each instruction's RVA against the `.sym` file's line records (sorted by address). A line record `<addr> <size> <line> <file_num>` covers `[addr, addr+size)`.

**Inline functions:** Match each instruction's RVA against INLINE records. Display inline function entry/exit boundaries.

**Call target resolution:** For `call` and `jmp` instructions:
1. Compute the absolute target address from the instruction encoding.
2. Look up the target address in the `.sym` file's FUNC and PUBLIC records.
3. If resolved, append the target symbol name as a comment (e.g., `; nsAtom::ToString`).
4. For indirect calls (`call [rax]`, `call qword ptr [rip+0x...]`), annotate with `; indirect call` (target unknown at static analysis time).

**PLT/IAT resolution:** For calls through the PLT (Linux) or IAT (Windows), attempt to resolve the import name from the binary's import tables.

---

## 7. Output Formats

### 7.1. Text Format

Designed to be readable by both humans and AI agents. Uses a consistent structure:

```
; Module: <code_file> (<debug_file> / <debug_id>)
; Function: <function_name> (RVA: <addr>, size: <size>)
; Source: <source_file>
; Architecture: <arch>
; Data sources: <binary+sym | binary | sym>
;
; <source_file>:<line>
<addr>:  <mnemonic>  <operands>              ; <annotation>
```

Conventions:
- Comment lines start with `;`.
- The highlight marker `==>` appears before the address on the highlighted line.
- Source file/line annotations appear as comment lines before the first instruction of each source line group.
- Inline function boundaries appear as `; [inline] <name> (<file>:<line>)` and `; [end inline] <name>`.
- Empty lines separate logical blocks (e.g., between basic blocks or source lines).

### 7.2. JSON Format

A structured JSON object as described in section 4.1. All addresses are hex strings with `0x` prefix. The `instructions` array preserves instruction order. This format is intended for programmatic consumption by AI agents that may want to filter, search, or cross-reference instructions.

---

## 8. Caching

### 8.1. Cache Location

Default cache directory (in order of precedence):

1. `--cache-dir <PATH>` command-line option.
2. `SYMDIS_CACHE_DIR` environment variable.
3. `_NT_SYMBOL_PATH` environment variable (Windows): parse the `SRV*<cache>*<server>` entries and use the first local cache path found.
4. Platform defaults:
   - Windows: `%LOCALAPPDATA%\symdis\cache`
   - Linux: `$XDG_CACHE_HOME/symdis` (or `~/.cache/symdis`)
   - macOS: `~/Library/Caches/symdis`

### 8.2. Cache Layout

```
<cache_root>/
  symbols/
    <debug_file>/<debug_id>/<filename>.sym
  binaries/
    <code_file>/<code_id>/<filename>
  pdb/
    <pdb_name>/<guid_age>/<filename>.pdb
  miss/
    <hash>.miss     # Negative cache marker
```

### 8.3. Cache Behavior

- Downloaded files are stored atomically (write to temp file, then rename) to prevent corruption from interrupted downloads.
- Negative results (HTTP 404) are cached as `.miss` marker files with a TTL (default: 24 hours, configurable via `--miss-ttl`).
- No automatic eviction policy. Users manage cache size via `symdis cache clear`.

### 8.4. Respecting Existing Caches

On Windows, if `_NT_SYMBOL_PATH` is configured, `symdis` checks those cache directories first before downloading. This avoids redundant downloads when the user also uses WinDbg, Visual Studio, or other tools that share the system symbol cache.

---

## 9. Configuration

### 9.1. Configuration File

Optional configuration file at:
- Windows: `%APPDATA%\symdis\config.toml`
- Linux/macOS: `$XDG_CONFIG_HOME/symdis/config.toml` (or `~/.config/symdis/config.toml`)

```toml
[cache]
dir = "D:\\SymbolCache\\symdis"
miss_ttl_hours = 48

[symbols]
# Symbol servers, tried in order
servers = [
    "https://symbols.mozilla.org/",
    "https://msdl.microsoft.com/download/symbols",
]

# debuginfod servers for Linux modules
debuginfod_urls = [
    "https://debuginfod.elfutils.org/",
]

[disassembly]
syntax = "intel"       # "intel" or "att"
max_instructions = 2000

[output]
format = "text"        # "text" or "json"

[network]
timeout_seconds = 30
max_concurrent_downloads = 4
user_agent = "symdis/0.1"
```

### 9.2. Environment Variables

| Variable | Description |
|---|---|
| `SYMDIS_CACHE_DIR` | Override cache directory |
| `SYMDIS_CONFIG` | Override config file path |
| `SYMDIS_SYMBOL_SERVERS` | Comma-separated list of symbol server URLs |
| `DEBUGINFOD_URLS` | Space-separated debuginfod server URLs (standard variable, shared with other tools) |
| `_NT_SYMBOL_PATH` | Windows symbol path (read-only; used for cache lookup, not modified) |

### 9.3. Precedence

Command-line flags > Environment variables > Config file > Built-in defaults.

---

## 10. Platform Support Matrix

### Binary Availability by Platform

| Platform | Binary source | Symbol source | Disassembly support |
|---|---|---|---|
| Windows x86/x64 | Microsoft Symbol Server, Mozilla Tecken (code-file/code-id) | Mozilla Tecken (`.sym`), Microsoft Symbol Server (PDB) | Full |
| Windows ARM64 | Same as above | Same as above | Full |
| Linux x86/x64 | debuginfod, Mozilla Tecken (if uploaded) | Mozilla Tecken (`.sym`), debuginfod | Full (when binary available) |
| Linux ARM/AArch64 | debuginfod | Mozilla Tecken (`.sym`), debuginfod | Full (when binary available) |
| macOS x86-64 | Mozilla Tecken (if uploaded) | Mozilla Tecken (`.sym`) | Depends on binary availability |
| macOS AArch64 | Mozilla Tecken (if uploaded) | Mozilla Tecken (`.sym`) | Depends on binary availability |
| Android ARM/AArch64 | Mozilla Tecken (if uploaded) | Mozilla Tecken (`.sym`) | Depends on binary availability |

**Note:** Windows has the best binary availability because both Microsoft and Mozilla make PE files accessible via their symbol servers. Linux has reasonable support via debuginfod for distribution packages. macOS and Android have the weakest binary availability — Mozilla may not upload raw binaries to Tecken for these platforms, limiting disassembly to cases where the binary can be obtained from other sources (e.g., local builds).

### Fallback Behavior

When the native binary is unavailable but the `.sym` file is:
- Function name, address, and size are still reported.
- Source file/line mapping is still available.
- Inline function information is still available.
- The `instructions` array is empty (no disassembly possible).
- The `source` field is set to `"sym"`.

---

## 11. Error Handling

### Error Categories

| Category | Example | Behavior |
|---|---|---|
| Module not found | No `.sym` or binary on any server | Return error with list of servers tried and HTTP status codes |
| Symbol file not found | Binary available but no `.sym` | Disassemble without annotations; `source: "binary"` |
| Binary not found | `.sym` available but no binary | Return symbol info without disassembly; `source: "sym"` |
| Function not found | `--function` name not in symbol table | Return error listing similar function names (fuzzy suggestions) |
| Offset out of range | `--offset` beyond module size | Return error with module address range |
| Network error | Timeout, DNS failure | Return error with details; use cached data if available (even if stale) |
| Unsupported architecture | e.g., MIPS | Return error indicating unsupported architecture |
| Corrupted file | Downloaded file fails parsing | Delete from cache, retry once, then return error |

### Error Output (JSON)

```json
{
  "error": {
    "code": "BINARY_NOT_FOUND",
    "message": "Native binary not available for xul.pdb/44E4EC8C2F41492B9369D6B9A059577C2",
    "details": {
      "servers_tried": [
        {"url": "https://symbols.mozilla.org/xul.dll/5CF2591C6859000/xul.dll", "status": 404},
        {"url": "https://msdl.microsoft.com/download/symbols/xul.dll/5CF2591C6859000/xul.dll", "status": 404}
      ]
    }
  },
  "partial_result": {
    "function": {
      "name": "mozilla::dom::Element::SetAttribute",
      "address": "0x1a3e80",
      "size": "0x120"
    },
    "source": "sym"
  }
}
```

Partial results are always returned when possible. The `partial_result` field is present whenever some useful information was obtained despite the error.

---

## 12. Implementation

### Language and Dependencies

**Language:** Rust

**Key crates:**

| Crate | Purpose |
|---|---|
| `clap` | CLI argument parsing |
| `goblin` | Cross-platform binary parsing (PE, ELF, Mach-O) |
| `capstone` | Multi-architecture disassembly engine |
| `reqwest` | HTTP client for symbol server requests |
| `tokio` | Async runtime for concurrent downloads |
| `serde` / `serde_json` | JSON serialization/deserialization |
| `cab` | CAB archive decompression (for Microsoft compressed symbols) |
| `flate2` | gzip decompression |
| `symbolic-common`, `symbolic-debuginfo` | Breakpad `.sym` file parsing (from the Sentry `symbolic` project) |
| `cpp_demangle` / `rustc-demangle` | C++ and Rust symbol demangling |

### Project Structure

```
symdis/
├── Cargo.toml
├── src/
│   ├── main.rs              # CLI entry point, argument parsing
│   ├── commands/
│   │   ├── mod.rs
│   │   ├── disasm.rs         # disasm command
│   │   ├── lookup.rs         # lookup command
│   │   ├── info.rs           # info command
│   │   ├── fetch.rs          # fetch command
│   │   └── cache.rs          # cache management
│   ├── symbols/
│   │   ├── mod.rs
│   │   ├── breakpad.rs       # Breakpad .sym file parser
│   │   ├── resolver.rs       # Symbol resolution pipeline
│   │   └── id_convert.rs     # Debug ID / Build ID conversions
│   ├── fetch/
│   │   ├── mod.rs
│   │   ├── tecken.rs         # Mozilla symbol server client
│   │   ├── microsoft.rs      # Microsoft symbol server client
│   │   ├── debuginfod.rs     # debuginfod client
│   │   └── cache.rs          # Cache management
│   ├── binary/
│   │   ├── mod.rs
│   │   ├── pe.rs             # PE file handling
│   │   ├── elf.rs            # ELF file handling
│   │   └── macho.rs          # Mach-O file handling
│   ├── disasm/
│   │   ├── mod.rs
│   │   ├── engine.rs         # Capstone wrapper
│   │   └── annotate.rs       # Annotation engine
│   ├── output/
│   │   ├── mod.rs
│   │   ├── text.rs           # Text formatter
│   │   └── json.rs           # JSON formatter
└── tests/
    ├── integration/
    └── fixtures/
```

### Build and Distribution

- Single statically-linked binary (no runtime dependencies except system libraries).
- Cross-compile targets: `x86_64-pc-windows-msvc`, `x86_64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`.
- Distribute via GitHub releases and `cargo install symdis`.

---

## 13. Future Extensions

The following features are out of scope for v0.1 but may be added later:

### 13.1. Crash Stats Integration

Direct integration with Mozilla's Crash Stats (Socorro) API to fetch processed crash reports by crash ID, eliminating the need for the user to manually download the JSON.

### 13.2. Decompilation

Integration with a decompilation engine (e.g., Ghidra headless mode or a Rust-native decompiler) to produce C-like pseudocode instead of or in addition to disassembly.

### 13.3. Control Flow Graph

Generate a text-based or DOT-format control flow graph for a function, showing basic blocks and edges. Useful for understanding complex branching logic.

### 13.4. Diff Mode

Compare the disassembly of the same function across two different builds (e.g., to see what changed between the version that crashes and a fixed version).

### 13.5. Interactive / Server Mode

A long-running mode where `symdis` keeps modules loaded in memory and accepts commands over stdin or a local socket. This would eliminate the overhead of re-parsing large files on each invocation and would be beneficial for AI agents making many sequential queries about the same module.

### 13.6. Binary Archive Fetching

For platforms where symbol servers don't host raw binaries (macOS, Android), fetch the full build archive from `archive.mozilla.org` and extract the needed binary. This requires mapping debug IDs to build versions, which could be done via the Crash Stats `ProductVersions` API or by querying buildhub.

### 13.7. Cross-Reference Database

Build a local index of all symbols in frequently-queried modules to enable fast cross-reference lookups (e.g., "find all callers of function X").

### 13.8. Register State Overlay

Accept register values from a crash report and annotate the disassembly with known register contents at each instruction (basic dataflow analysis from the crash point backwards).

---

## Appendix A: Breakpad Symbol File Quick Reference

Key record types that `symdis` parses from `.sym` files:

```
MODULE <os> <arch> <debug_id> <name>
FILE <index> <source_path>
FUNC [m] <addr> <size> <param_size> <name>
<addr> <size> <line> <file_index>              (line record, follows FUNC)
PUBLIC [m] <addr> <param_size> <name>
INLINE_ORIGIN <index> <name>
INLINE <depth> <call_line> <call_file> <origin_index> [<addr> <size>]+
```

All addresses are hexadecimal, lowercase, no `0x` prefix, relative to the module's load address.

---

## Appendix B: Debug ID Conversion Examples

### Windows

```
PDB GUID:  {44E4EC8C-2F41-492B-9369-D6B9A059577C}
PDB Age:   2
Debug ID:  44E4EC8C2F41492B9369D6B9A059577C2
```

The debug ID is the GUID (hex digits only, uppercase) concatenated with the age in hex.

### Linux

```
ELF Build ID:  b7dc60e91588d8a54c4c44205044422e (20 bytes, shown as 40 hex chars)
First 16 bytes: b7dc60e9 1588 d8a5 4c4c44205044422e

Byte-swap first 3 GUID fields:
  Data1 (4 bytes LE): b7dc60e9 → E960DCB7
  Data2 (2 bytes LE): 1588      → 8815
  Data3 (2 bytes LE): d8a5      → A5D8
  Data4 (8 bytes):    4c4c44205044422e (unchanged)

Debug ID:  E960DCB78815A5D84C4C44205044422E0
                                            ^ age is always 0
```

### macOS

```
Mach-O UUID:  E960DCB7-8815-A5D8-4C4C-44205044422E
Debug ID:     E960DCB78815A5D84C4C44205044422E0
                                              ^ age is always 0
```
