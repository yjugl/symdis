# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
cargo build                          # Build
cargo clippy -- -D warnings          # Lint (must pass with zero warnings)
cargo test                           # Run all 149 unit tests
cargo test symbols::breakpad         # Run tests in a specific module
cargo test test_rva_to_offset        # Run a single test by name
cargo run -- disasm --help           # Run CLI with args
```

## Project Status

Phases 0-15 of the [implementation plan](IMPLEMENTATION.md) are complete. The `disasm` command works end-to-end for Windows (PE), Linux (ELF), and macOS (Mach-O) modules: fetch sym+binary from symbol servers, find a function, disassemble, annotate with source lines/call targets/inlines/highlight, and print text or JSON output (`--format text|json`). Mach-O supports fat (universal) binaries with automatic arch selection. The FTP archive fallback supports both Linux (tar.xz) and macOS (PKG/XAR/cpio). The `lookup` and `info` commands are also implemented. C++/Rust symbol demangling is applied at display time (`--no-demangle` to disable). Configuration is loaded from a TOML config file, environment variables, and CLI flags with layered precedence (defaults < config file < env vars < CLI). Structured logging via `tracing` outputs to stderr at configurable verbosity (`-v` for info, `-vv` for debug). The `--offline` flag restricts operation to cached data only. HTML error page detection prevents caching corrupted downloads. Empty functions (size 0) are handled gracefully. The remaining `fetch` command is stubbed but not yet implemented. The `frames` command has been removed from the plan — the AI agent selects interesting frames and calls `disasm` individually.

`#![allow(dead_code)]` is set in `main.rs` because many pub items are defined ahead of use for later phases. Remove this once all phases are complete.

## Architecture

**Data flow for `disasm` command** (`commands/disasm.rs`):
1. Initialize tracing subscriber (verbosity from `-v`/`-vv`), resolve `Config` (TOML file + env vars + CLI flags), build HTTP client + cache
2. Concurrently fetch `.sym` file and native binary (`tokio::join!`)
3. Parse `.sym` → `SymFile`, parse binary → `PeFile`, `ElfFile`, or `MachOFile` (via `BinaryFile` trait)
4. Find target function by name (HashMap lookup) or offset (binary search)
5. Extract code bytes at function's RVA, disassemble via Capstone
6. Annotate: source lines → call targets → inlines → highlight (`disasm/annotate.rs`)
7. Demangle function name, call target names, and inline frame names (`demangle.rs`)
8. Format and print text or JSON output (dispatched via `--format`)

**Graceful degradation**: sym+binary → full disassembly; binary-only → raw disassembly; sym-only → metadata without instructions; neither → error.

**Key modules**:
- `config.rs` — TOML config file parsing (`toml 0.8`); `Config::resolve()` merges defaults < config file < env vars < CLI flags; `_NT_SYMBOL_PATH` parsing for cache dir; config file located via `SYMDIS_CONFIG` env var or platform default (`%APPDATA%\symdis\config.toml` / `~/.config/symdis/config.toml`)
- `cache.rs` — Flat WinDbg-compatible layout (`<root>/<file>/<id>/<file>`); atomic writes via tempfile; negative cache markers with configurable TTL
- `fetch/` — Orchestrator tries Tecken then Microsoft symbol server; both clients handle CAB-compressed downloads (`.dl_`/`.pd_` variants); server URLs parameterized from config; shared `compress_filename`/`decompress_cab` in `fetch/mod.rs`; `is_html_response()` detects corrupted downloads; offline mode skips network after cache miss; cache hit/miss logging via `tracing`
- `fetch/debuginfod.rs` — debuginfod client for Linux executables; server URLs from config (sourced from `DEBUGINFOD_URLS` env var or config file)
- `fetch/archive.rs` — Mozilla FTP archive client; downloads `.tar.xz` (Linux) or `.pkg` (macOS) build archives; extracts binaries; verifies ELF build IDs and Mach-O UUIDs; archive caching avoids re-downloading for multiple binaries from the same release
- `symbols/breakpad.rs` — Line-by-line parser for `.sym` files; functions and publics sorted by address for binary search; name→index HashMap for exact lookup; `resolve_address` caps PUBLIC symbol distance at 64KB; `get_inline_at` returns active inline frames; `SymFileSummary` for lightweight scanning
- `symbols/id_convert.rs` — Debug ID ↔ Build ID conversion (GUID byte-swapping for ELF)
- `binary/pe.rs` — Goblin-based PE parser implementing `BinaryFile` trait; RVA-to-file-offset via section table walk; IAT import resolution for call target annotation
- `binary/elf.rs` — Goblin-based ELF parser implementing `BinaryFile` trait; VA-to-offset via PT_LOAD segments; PLT import mapping for call target annotation
- `binary/macho.rs` — Goblin-based Mach-O parser implementing `BinaryFile` trait; fat (universal) binary support with arch selection; VA-to-offset via segments; export/import resolution; UUID extraction for build verification
- `demangle.rs` — C++/Rust symbol demangling via `cpp_demangle` (Itanium ABI) and `rustc-demangle`; applied at display time, not at parse/storage time; `--no-demangle` opt-out
- `disasm/engine.rs` — Capstone wrapper supporting x86/x86_64/ARM/ARM64 with Intel or ATT syntax; extracts call targets from direct call/jmp instructions
- `disasm/annotate.rs` — Annotation pipeline: source lines, call target resolution (FUNC/PUBLIC/IAT/PLT), inline frame tracking, highlight with mid-instruction range matching
- `output/text.rs` — Text formatter rendering source line comments, call target annotations, inline enter/exit markers, highlight (`==>`) marker; also defines shared `ModuleInfo`, `FunctionInfo`, `DataSource` types
- `output/json.rs` — JSON formatter with dedicated serde structs; hex-string addresses, hex-encoded bytes, `skip_serializing_if` for optional fields; includes `format_json_error` for structured error output

## Key Conventions

- **Every new `.rs` file must start with the MPL 2.0 license header:**
  ```rust
  // This Source Code Form is subject to the terms of the Mozilla Public
  // License, v. 2.0. If a copy of the MPL was not distributed with this
  // file, You can obtain one at http://mozilla.org/MPL/2.0/.
  ```
- All commands are async (`async fn run`) and return `anyhow::Result<()>` with `.context()` for error messages
- `.sym` filename derivation: `xul.pdb` → `xul.sym`, `libxul.so` → `libxul.so.sym` (strip `.pdb` suffix, else append `.sym`)
- Hex addresses in `.sym` files have no `0x` prefix; parsed with `u64::from_str_radix(s, 16)`
- INLINE records in `.sym` files must follow their parent FUNC (before the next FUNC)
- Breakpad FUNC/PUBLIC may have optional `m` flag after keyword — parse and ignore

## Crate Version Constraints

- **goblin 0.9** (not 0.10): `Export.rva` is `usize`, not `Option<usize>`
- **capstone 0.13** (not 0.14): stable API
- **reqwest 0.12** with `rustls-tls`
- **cab 0.6** for Microsoft CAB decompression
- **xz2 0.1** + **tar 0.4** for Linux `.tar.xz` archive extraction
- **quick-xml 0.37** + **cpio_reader 0.1** for macOS `.pkg` (XAR/cpio) archive extraction
- **cpp_demangle 0.4** + **rustc-demangle 0.1** for C++/Rust symbol demangling
- **toml 0.8** for TOML config file parsing
- **tracing 0.1** + **tracing-subscriber 0.3** for structured logging
- **edition = "2021"** (not 2024)

## Reference

- [SPEC.md](SPEC.md) — Full specification (commands, output formats, symbol resolution pipeline, error handling)
- [IMPLEMENTATION.md](IMPLEMENTATION.md) — 16-phase build plan with acceptance criteria per phase
