# symdis

A CLI tool for disassembling functions from Mozilla crash reports. Given a module identifier and either a function name or an offset, `symdis` fetches the binary and symbol information from public servers, disassembles the target function, and annotates it with source lines, call targets, and inline frames.

Designed primarily for use by AI agents analyzing [Socorro/Crash Stats](https://crash-stats.mozilla.org/) crash reports, but also useful for manual crash triage and reverse engineering.

## Features

- **Fetch symbols and binaries** from Mozilla's [Tecken](https://symbols.mozilla.org/) symbol server, Microsoft's public symbol server, [debuginfod](https://sourceware.org/elfutils/Debuginfod.html) servers, the [Snap Store](https://snapcraft.io/) (Ubuntu snaps), and Mozilla's FTP archive — with automatic CAB decompression, `.tar.xz` extraction, `.pkg` (XAR/cpio) extraction, and `.apk` (ZIP) extraction
- **Not limited to Mozilla modules**: Mozilla's crash infrastructure generates `.sym` files from Microsoft PDBs for all modules seen in crash stacks, so Windows system DLLs (ntdll, kernel32, kernelbase, etc.) are fully supported. Other third-party modules may also have symbols available
- **PDB support**: fetch and parse PDB files directly from Microsoft's symbol server or Tecken (`--pdb` flag); auto-fallback when `.sym` is unavailable for Windows modules; inline frames, srcsrv VCS paths, MSVC-demangled function signatures
- **Windows, Linux, macOS, and Android** module support: PE (via section table), ELF (via PT_LOAD segments), and Mach-O (including fat/universal binaries) binary formats; Android support for Fenix (Firefox for Android) and Focus (Firefox Focus) via APK extraction; Windows kernel drivers (`.sys` files) supported with PDB auto-fallback
- **Find functions** by exact name, substring match (`--fuzzy`), or by RVA/offset; searches FUNC records, PUBLIC symbols (with demangling), and binary exports
- **Disassemble** x86, x86-64, ARM32, and AArch64 code via [Capstone](https://www.capstone-engine.org/); ARM32 Thumb-2 mode auto-detected from ELF symbol metadata
- **Annotate** instructions with source file/line, resolved call targets (FUNC/PUBLIC/IAT/PLT/GOT/dylib imports), and inline function boundaries
- **Resolve indirect calls**: IAT imports on x86/x86-64, PLT stubs on ARM/AArch64 ELF, `__stubs` entries on Mach-O, GOT slots on Linux ELF, and AArch64 ADRP+LDR+BLR/BR sequences across all platforms
- **Demangle** C++ (Itanium ABI), Rust, and MSVC (`?Name@...`) symbol names automatically (`--no-demangle` to disable)
- **Highlight** a specific offset (e.g., a crash address) in the output
- **Graceful degradation**: binary+sym gives full annotated disassembly; binary-only gives raw disassembly; sym-only gives function metadata
- **Text and JSON** output formats (`--format text|json`)
- **Configurable** via TOML config file, environment variables, and CLI flags with layered precedence
- **Local cache** with WinDbg-compatible layout, atomic writes, negative-cache markers, and `_NT_SYMBOL_PATH` integration

## Installation

Pre-built binaries (fastest):

```bash
cargo binstall symdis
```

From source:

```bash
cargo install symdis
```

Or clone and build:

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

Run `symdis <command> --help` for full documentation, crash report field mappings, and more examples.

### disasm

The primary command. See the [Quick Start](#quick-start) section above for common examples. Additional examples:

```bash
# Non-Mozilla module (Windows system DLL):
symdis disasm \
    --debug-file ntdll.pdb \
    --debug-id 08A413EE85E91D0377BA33DC3A2641941 \
    --code-file ntdll.dll --code-id 5b6dddee267000 \
    --function NtCreateFile

# Windows kernel driver (PDB auto-fallback, .pdata function bounds):
symdis disasm \
    --debug-file win32kfull.pdb \
    --debug-id 874E89B5C0960A8CE25E012F602168591 \
    --code-file win32kfull.sys --code-id 73E41EF8412000 \
    --function xxxResolveDesktop

# Fenix (Firefox for Android) — MUST use --product fenix:
symdis disasm \
    --debug-file libxul.so \
    --debug-id 9E915B1A91D7345C4FF0753CF13E53280 \
    --code-file libxul.so \
    --code-id 1a5b919ed7915c344ff0753cf13e532814635a84 \
    --product fenix \
    --version 147.0.3 --channel release \
    --offset 0x03fc39d4 --highlight-offset 0x03fc39d4

# Use PDB for richer symbol data (Windows modules only):
symdis disasm \
    --debug-file ntdll.pdb \
    --debug-id 08A413EE85E91D0377BA33DC3A2641941 \
    --code-file ntdll.dll --code-id 5b6dddee267000 \
    --function NtCreateFile --pdb
```

### lookup

Resolves offsets to symbols or symbols to addresses using the `.sym` file only (no binary needed). Searches both FUNC and PUBLIC symbols.

```bash
# Resolve an offset to a symbol name:
symdis lookup \
    --debug-file xul.pdb \
    --debug-id EE20BD9ABD8D048B4C4C44205044422E1 \
    --offset 0x0144c8d2

# Find a function's address by name (substring match):
symdis lookup \
    --debug-file xul.pdb \
    --debug-id EE20BD9ABD8D048B4C4C44205044422E1 \
    --function ProcessIncomingMessages --fuzzy
```

### info

Shows module metadata: OS, architecture, function count, and whether sym/binary files are available.

```bash
# Check module metadata and sym/binary availability:
symdis info \
    --debug-file xul.pdb \
    --debug-id EE20BD9ABD8D048B4C4C44205044422E1 \
    --code-file xul.dll --code-id 68d1a3cd87be000

# JSON output:
symdis info \
    --debug-file xul.pdb \
    --debug-id EE20BD9ABD8D048B4C4C44205044422E1 \
    --code-file xul.dll --code-id 68d1a3cd87be000 \
    --format json
```

### fetch

Pre-fetches sym and binary into the local cache so subsequent `disasm` calls are instant.

```bash
# Pre-fetch a Windows module:
symdis fetch \
    --debug-file xul.pdb \
    --debug-id EE20BD9ABD8D048B4C4C44205044422E1 \
    --code-file xul.dll --code-id 68d1a3cd87be000

# Pre-fetch a Linux module with FTP archive fallback:
symdis fetch \
    --debug-file libxul.so \
    --debug-id 669D6B010E4BF04FF9B3F43CCF735A340 \
    --code-file libxul.so \
    --code-id 016b9d664b0e4ff0f9b3f43ccf735a3482db0fd6 \
    --version 147.0.3 --channel release

# Pre-fetch including PDB file:
symdis fetch \
    --debug-file ntdll.pdb \
    --debug-id 08A413EE85E91D0377BA33DC3A2641941 \
    --code-file ntdll.dll --code-id 5b6dddee267000 \
    --pdb
```

### cache

Manage the local cache.

```bash
symdis cache path                             # Print cache directory path
symdis cache size                             # Show total cache size
symdis cache clear                            # Delete all cached files
symdis cache clear --older-than 30            # Delete files older than 30 days
symdis cache list --debug-file xul.pdb        # List cached artifacts for a module
```

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

## Update Check

On each run, symdis checks [crates.io](https://crates.io/crates/symdis) in the background for a newer version. If one is found, a notice is printed to stderr after the command completes. The check is cached for 24 hours and can be disabled by setting `MOZTOOLS_UPDATE_CHECK=0`.

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

## License

This project is licensed under the [Mozilla Public License 2.0](LICENSE).
