# symdis

A CLI tool for disassembling functions from Mozilla crash reports. Given a module identifier and either a function name or an offset, `symdis` fetches the binary and symbol information from public servers, disassembles the target function, and annotates it with source lines, call targets, and inline frames.

Designed primarily for use by AI agents analyzing [Socorro/Crash Stats](https://crash-stats.mozilla.org/) crash reports, but also useful for manual crash triage and reverse engineering.

## Features

- **Fetch symbols and binaries** from Mozilla's [Tecken](https://symbols.mozilla.org/) symbol server, Microsoft's public symbol server, [debuginfod](https://sourceware.org/elfutils/Debuginfod.html) servers, the [Snap Store](https://snapcraft.io/) (Ubuntu snaps), and Mozilla's FTP archive — with automatic CAB decompression, `.tar.xz` extraction, `.pkg` (XAR/cpio) extraction, and `.apk` (ZIP) extraction
- **Not limited to Mozilla modules**: Mozilla's crash infrastructure generates `.sym` files from Microsoft PDBs for all modules seen in crash stacks, so Windows system DLLs (ntdll, kernel32, kernelbase, etc.) are fully supported. Other third-party modules may also have symbols available
- **Windows, Linux, macOS, and Android** module support: PE (via section table), ELF (via PT_LOAD segments), and Mach-O (including fat/universal binaries) binary formats; Android support for Fenix (Firefox for Android) and Focus (Firefox Focus) via APK extraction
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

From source:

```bash
git clone https://github.com/yjugl/symdis.git
cd symdis
cargo install --path .
```

## Quick Start

```bash
# Disassemble the function containing a specific offset, with crash address highlight
symdis disasm \
    --debug-file xul.pdb \
    --debug-id EE20BD9ABD8D048B4C4C44205044422E1 \
    --code-file xul.dll --code-id 68d1a3cd87be000 \
    --offset 0x0144c8d2 --highlight-offset 0x0144c8d2

# Fuzzy name search
symdis disasm \
    --debug-file xul.pdb \
    --debug-id EE20BD9ABD8D048B4C4C44205044422E1 \
    --code-file xul.dll --code-id 68d1a3cd87be000 \
    --function ProcessIncomingMessages --fuzzy

# Linux module with FTP archive fallback
symdis disasm \
    --debug-file libxul.so \
    --debug-id 669D6B010E4BF04FF9B3F43CCF735A340 \
    --code-file libxul.so \
    --code-id 016b9d664b0e4ff0f9b3f43ccf735a3482db0fd6 \
    --version 147.0.3 --channel release \
    --offset 0x4616fda --highlight-offset 0x4616fda

# macOS module (fat/universal binary from PKG archive)
symdis disasm \
    --debug-file XUL \
    --debug-id EA25538ED7533E56A4263F6D7050F3D20 \
    --code-file XUL \
    --code-id ea25538ed7533e56a4263f6d7050f3d2 \
    --version 140.6.0esr --channel esr \
    --offset 0x1cb6dd --highlight-offset 0x1cb6dd

# JSON output
symdis disasm \
    --debug-file xul.pdb \
    --debug-id EE20BD9ABD8D048B4C4C44205044422E1 \
    --code-file xul.dll --code-id 68d1a3cd87be000 \
    --function ProcessIncomingMessages --fuzzy \
    --format json
```

## Example Output

### Text (default)

Output is abbreviated — the tool prints all instructions in the function.

```
; Module: xul.dll (xul.pdb / EE20BD9ABD8D048B4C4C44205044422E1)
; Function: IPC::Channel::ChannelImpl::ProcessIncomingMessages(...) (RVA: 0x144c490, size: 0xa57)
; Source: hg:hg.mozilla.org/releases/mozilla-esr140:ipc/chromium/src/chrome/common/ipc_channel_win.cc:0b8c...
; Architecture: x86
; Data sources: binary+sym
;
    ; .../ipc_channel_win.cc:...:264
    0x0144c490:  push    ebp
    0x0144c491:  mov     ebp, esp
    0x0144c493:  push    ebx
    0x0144c494:  push    edi
    0x0144c495:  push    esi
    0x0144c496:  and     esp, 0xfffffff8
    0x0144c499:  sub     esp, 0xf8
    ; .../ipc_channel_win.cc:...:269
    0x0144c4b8:  test    cl, cl
    ...
    ; [inline] mozilla::UniquePtr<...>::get() const (.../ipc_channel_win.cc:...:305)
    ; .../mfbt/UniquePtr.h:...:399
    0x0144c4d5:  mov     ebx, dword ptr [edi + 0x8c]
    ; [end inline] mozilla::UniquePtr<...>::get() const
    ...
    0x0144c801:  call    0x1463290              ; IPC::Channel::ChannelImpl::AcceptHandles(IPC::Message&)
    ...
==> 0x0144c8cd:  call    dword ptr [0x173b5260]  ; [indirect]
    0x0144c8d3:  add     esp, 4
```

### JSON

```json
{
  "module": {
    "debug_file": "xul.pdb",
    "debug_id": "EE20BD9ABD8D048B4C4C44205044422E1",
    "code_file": "xul.dll",
    "arch": "x86"
  },
  "function": {
    "name": "IPC::Channel::ChannelImpl::ProcessIncomingMessages(...)",
    "address": "0x144c490",
    "size": "0xa57",
    "source_file": "hg:hg.mozilla.org/releases/mozilla-esr140:ipc/chromium/..."
  },
  "instructions": [
    {
      "address": "0x144c490",
      "bytes": "55",
      "mnemonic": "push",
      "operands": "ebp",
      "source_file": "hg:hg.mozilla.org/releases/mozilla-esr140:ipc/chromium/...",
      "source_line": 264,
      "highlighted": false,
      "inline_frames": []
    },
    {
      "address": "0x144c801",
      "bytes": "e88a6a0000",
      "mnemonic": "call",
      "operands": "0x1463290",
      "source_file": "hg:hg.mozilla.org/releases/mozilla-esr140:ipc/chromium/...",
      "source_line": 356,
      "highlighted": false,
      "call_target": "IPC::Channel::ChannelImpl::AcceptHandles(IPC::Message&)",
      "inline_frames": []
    }
  ],
  "source": "binary+sym",
  "warnings": []
}
```

## Commands

| Command | Description |
|---|---|
| `disasm` | Disassemble a function from a module |
| `lookup` | Resolve an offset to a symbol, or a name to an address |
| `info` | Show module metadata |
| `fetch` | Pre-fetch symbols and binary for a module |
| `cache` | Manage the local cache (`path`, `size`, `clear`, `list`) |

## Global Options

| Option | Default | Description |
|---|---|---|
| `--cache-dir <PATH>` | auto-detected | Cache directory path |
| `--format <FMT>` | `text` | Output format: `text` or `json` |
| `--no-demangle` | off | Disable C++/Rust symbol demangling |
| `-v` / `-vv` | off | Verbose output (info / debug) |
| `--offline` | off | Skip network requests; use only cached data |

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
user_agent = "symdis/0.1.0"
offline = false
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

## Data and Privacy

symdis processes only **publicly available data**:

- **Inputs**: Module identifiers (debug file, debug ID, code file, code ID), function names, and offsets — all from the public portions of crash reports on [Crash Stats](https://crash-stats.mozilla.org/).
- **Downloads**: Symbol files and binaries from public symbol servers (Mozilla Tecken, Microsoft, debuginfod) and public archives (Mozilla FTP, Snap Store).
- **Does NOT process**: Minidumps, memory contents, crash annotations, user comments, URLs, email addresses, or any other [protected data](https://crash-stats.mozilla.org/documentation/protected_data_access/).

When using symdis — whether manually or through an AI agent — only provide data from **publicly accessible crash report fields** (stack traces, module lists, release information). Do not pass [protected crash report data](https://crash-stats.mozilla.org/documentation/protected_data_access/) (such as user comments, email addresses, or URLs from crash annotations) to symdis or to AI tools analyzing crash reports.

For Mozilla's policies on using AI tools in development, see [AI and Coding](https://firefox-source-docs.mozilla.org/contributing/ai-coding.html). For contribution guidelines, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Documentation

- [SPEC.md](SPEC.md) -- Full specification
- [IMPLEMENTATION.md](IMPLEMENTATION.md) -- Phased implementation plan

## License

This project is licensed under the [Mozilla Public License 2.0](LICENSE).
