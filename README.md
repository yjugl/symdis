# symdis

A CLI tool for disassembling functions from Mozilla crash reports. Given a module identifier and either a function name or an offset, `symdis` fetches the binary and symbol information from Mozilla's and Microsoft's symbol servers, disassembles the target function, and annotates it with source lines, call targets, and inline frames.

Designed primarily for use by AI agents analyzing [Socorro/Crash Stats](https://crash-stats.mozilla.org/) crash reports, but also useful for manual crash triage and reverse engineering.

## Features

- **Fetch symbols and binaries** from Mozilla's [Tecken](https://symbols.mozilla.org/) symbol server, Microsoft's public symbol server, [debuginfod](https://sourceware.org/elfutils/Debuginfod.html) servers, and Mozilla's FTP archive — with automatic CAB decompression, `.tar.xz` extraction, and `.pkg` (XAR/cpio) extraction
- **Windows, Linux, and macOS** module support: PE (via section table), ELF (via PT_LOAD segments), and Mach-O (including fat/universal binaries) binary formats
- **Find functions** by exact name, substring match (`--fuzzy`), or by RVA/offset
- **Disassemble** x86, x86-64, ARM32, and AArch64 code via [Capstone](https://www.capstone-engine.org/)
- **Annotate** instructions with source file/line, resolved call targets (FUNC/PUBLIC/IAT/PLT/dylib imports), and inline function boundaries
- **Demangle** C++ (Itanium ABI) and Rust symbol names automatically (`--no-demangle` to disable)
- **Highlight** a specific offset (e.g., a crash address) in the output
- **Graceful degradation**: binary+sym gives full annotated disassembly; binary-only gives raw disassembly; sym-only gives function metadata
- **Text and JSON** output formats (`--format text|json`)
- **Configurable** via TOML config file, environment variables, and CLI flags with layered precedence
- **Local cache** with WinDbg-compatible layout, atomic writes, negative-cache markers, and `_NT_SYMBOL_PATH` integration

## Installation

```bash
cargo install symdis
```

Or build from source:

```bash
git clone https://github.com/<owner>/symdis.git
cd symdis
cargo build --release
```

## Quick Start

```bash
# Disassemble a function by name
symdis disasm \
    --debug-file xul.pdb \
    --debug-id 44E4EC8C2F41492B9369D6B9A059577C2 \
    --function "mozilla::dom::Element::SetAttribute"

# Disassemble the function containing a specific offset, with highlight
symdis disasm \
    --debug-file ntdll.pdb \
    --debug-id 1EB9FACB04EA273BB24BA52C8B8D336A1 \
    --offset 0xa2c30 \
    --highlight-offset 0xa2c47

# Fuzzy name search
symdis disasm \
    --debug-file xul.pdb \
    --debug-id 44E4EC8C2F41492B9369D6B9A059577C2 \
    --function SetAttribute --fuzzy

# Linux module with FTP archive fallback
symdis disasm \
    --debug-file libxul.so \
    --debug-id 0200CE7B29CF2F761BB067BC519155A00 \
    --code-id 7bce0002cf29762f1bb067bc519155a0cb3f4a31 \
    --version 147.0.3 --channel release \
    --offset 0x3bb5231 --highlight-offset 0x3bb5231

# macOS module (fat/universal binary from PKG archive)
symdis disasm \
    --debug-file XUL \
    --debug-id 697EB30464C83C329FF3A1B119BAC88D0 \
    --code-id 697eb30464c83c329ff3a1b119bac88d \
    --version 147.0.3 --channel release \
    --offset 0x1c019fb --highlight-offset 0x1c019fb

# JSON output
symdis disasm \
    --debug-file ntdll.pdb \
    --debug-id 1EB9FACB04EA273BB24BA52C8B8D336A1 \
    --function NtCreateFile \
    --format json
```

## Example Output

### Text (default)

```
; Module: xul.dll (xul.pdb / 44E4EC8C2F41492B9369D6B9A059577C2)
; Function: mozilla::dom::Element::SetAttribute (RVA: 0x1a3e80, size: 0x120)
; Source: dom/base/Element.cpp
; Architecture: x86_64
; Data sources: binary+sym
;
    ; dom/base/Element.cpp:1234
    0x001a3e80:  push    rbp
    0x001a3e81:  mov     rbp, rsp
    0x001a3e84:  sub     rsp, 0x40
    ; dom/base/Element.cpp:1235
    0x001a3e88:  mov     qword ptr [rbp - 0x8], rcx
    ; [inline] mozilla::dom::Element::BeforeSetAttr (dom/base/Element.cpp:1180)
    0x001a3e90:  lea     rcx, [rbp - 0x38]
    0x001a3e94:  call    0x002b1200              ; nsAtom::ToString
    ; [end inline] mozilla::dom::Element::BeforeSetAttr
        ...
==> 0x001a3f00:  call    0x001b2340              ; nsContentUtils::SetNodeTextContent
        ...
    0x001a3f9f:  ret
```

### JSON

```json
{
  "module": {
    "debug_file": "xul.pdb",
    "debug_id": "44E4EC8C2F41492B9369D6B9A059577C2",
    "code_file": "xul.dll",
    "arch": "x86_64"
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
      "inline_frames": []
    }
  ],
  "source": "binary+sym",
  "warnings": []
}
```

## Commands

| Command | Description | Status |
|---|---|---|
| `disasm` | Disassemble a function from a module | Implemented |
| `lookup` | Resolve an offset to a symbol, or a name to an address | Implemented |
| `info` | Show module metadata | Implemented |
| `fetch` | Pre-fetch symbols and binary for a module | Planned |
| `cache` | Manage the local cache (`path`, `size`, `clear`) | Implemented |

## Global Options

| Option | Default | Description |
|---|---|---|
| `--cache-dir <PATH>` | auto-detected | Cache directory path |
| `--format <FMT>` | `text` | Output format: `text` or `json` |
| `--no-demangle` | off | Disable C++/Rust symbol demangling |
| `-v` / `-vv` | off | Verbose output (info / debug) |

## Configuration

Settings are resolved with layered precedence: **defaults < config file < environment variables < CLI flags**.

### Config File

Location (checked in order):
1. `SYMDIS_CONFIG` environment variable
2. Platform default: `%APPDATA%\symdis\config.toml` (Windows) or `~/.config/symdis/config.toml` (Linux/macOS)

```toml
[cache]
dir = "D:\\SymbolCache\\symdis"
miss_ttl_hours = 48

[symbols]
servers = [
    "https://symbols.mozilla.org/",
    "https://msdl.microsoft.com/download/symbols",
]
debuginfod_urls = ["https://debuginfod.elfutils.org/"]

[disassembly]
syntax = "intel"        # "intel" or "att"
max_instructions = 2000

[output]
format = "text"         # "text" or "json"

[network]
timeout_seconds = 30
user_agent = "symdis/0.1"
```

### Environment Variables

| Variable | Description |
|---|---|
| `SYMDIS_CONFIG` | Override config file path |
| `SYMDIS_CACHE_DIR` | Override cache directory |
| `SYMDIS_SYMBOL_SERVERS` | Comma-separated symbol server URLs |
| `DEBUGINFOD_URLS` | Space-separated debuginfod server URLs |
| `_NT_SYMBOL_PATH` | Windows symbol path (used for cache directory resolution) |

## Cache

Downloaded symbol files and binaries are cached locally. The cache directory is resolved in this order:

1. `--cache-dir` CLI flag
2. `SYMDIS_CACHE_DIR` environment variable
3. Config file `[cache] dir` setting
4. `_NT_SYMBOL_PATH` (Windows) -- uses the cache path from `SRV*<cache>*<server>` entries
5. Platform default (`%LOCALAPPDATA%\symdis\cache`, `~/.cache/symdis`, or `~/Library/Caches/symdis`)

The cache uses WinDbg-compatible flat layout (`<file>/<id>/<file>`) so it can be shared with other symbol tools.

## Documentation

- [SPEC.md](SPEC.md) -- Full specification
- [IMPLEMENTATION.md](IMPLEMENTATION.md) -- Phased implementation plan

## License

This project is licensed under the [Mozilla Public License 2.0](LICENSE).
