# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
cargo build                          # Build
cargo clippy -- -D warnings          # Lint (must pass with zero warnings)
cargo test                           # Run all unit tests
cargo test symbols::breakpad         # Run tests in a specific module
cargo test test_rva_to_offset        # Run a single test by name
cargo run -- disasm --help           # Run CLI with args
```

## After Making Changes

Always run these before proposing a commit:

```bash
cargo clippy -- -D warnings          # Must pass with zero warnings
cargo test                           # All tests must pass
```

Also verify:
- **`--help` is complete**: An AI agent without access to the source code relies on `--help` as its sole reference. Ensure all flags, fetch chain behavior, examples, and edge cases are documented in the `after_long_help` text in `commands/mod.rs`.
- **CLAUDE.md is up-to-date**: Update the Project Status, Architecture, and Key Conventions sections to reflect any new modules, commands, flags, or behavioral changes.

## Project Status

All commands are fully implemented and the project is ready for real-life testing. The `disasm` command works end-to-end for Windows (PE), Linux (ELF), and macOS (Mach-O) modules: fetch sym+binary from symbol servers, find a function, disassemble, annotate with source lines/call targets/inlines/highlight, and print text or JSON output (`--format text|json`). Symbol coverage is not limited to Mozilla modules — Tecken has `.sym` files for Microsoft-issued Windows system DLLs (ntdll, kernel32, kernelbase, etc.) because Mozilla's crash infrastructure automatically generates them from Microsoft PDBs. Other third-party modules may also have symbols when their vendors publish PDBs. Mach-O supports fat (universal) binaries with automatic arch selection. Binary fetch chain: Tecken → Microsoft (Windows PE only) → debuginfod (Linux) → Snap Store (Linux) → FTP archive (Linux tar.xz, macOS PKG/XAR/cpio, Android APK). When the sym file is unavailable, platform is inferred from code_id format (40-char hex → Linux, 32-char hex → macOS) so fallback sources are still attempted. The "Tried:" line in binary-not-found errors accurately lists only the sources that were actually attempted. Channel "default" (reported by some Linux distro builds in Socorro) is mapped to "release" for FTP archive lookup. Fenix (Firefox for Android) is supported via `--product fenix` with APK extraction. Focus (Firefox Focus for Android) is supported via `--product focus` with APK extraction. Ubuntu snap libraries are supported via the Snap Store backend (auto-detected or `--snap`). PDB symbol support: the `--pdb` flag fetches PDB files directly instead of `.sym`; without `--pdb`, PDB is auto-tried when `.sym` is unavailable for Windows modules. PDB fetch chain: cache → Tecken (uncompressed + CAB) → Microsoft Symbol Server (uncompressed + CAB), using extended timeout (archive_timeout_seconds) for large PDBs. PDB data is converted into the existing `SymFile` struct so the annotation pipeline is unchanged. PDB inline frame tracking is supported via `InlineSiteSymbol` records and the IPI (ID information) stream; code ranges are extracted from binary annotations and inlinee names are resolved from the IPI stream. MSVC-decorated symbol names (`?Name@...`) are demangled via the `msvc-demangler` crate alongside Itanium ABI and Rust demangling. Remaining PDB limitations vs `.sym`: sparser source line coverage (pdb crate panics on some modules in large PDBs — caught and skipped silently), raw build paths instead of VCS paths, function names without parameter signatures, no call site file/line for inline frames. For Mozilla modules where `.sym` exists on Tecken, `.sym` gives better output; PDB is primarily useful for non-Mozilla Windows modules with no `.sym` on Tecken. The `lookup`, `info`, and `fetch` commands are implemented. The `cache` command supports `path`, `size`, `clear` (with `--older-than`), and `list`. C++/Rust/MSVC symbol demangling is applied at display time (`--no-demangle` to disable). Configuration is loaded from a TOML config file, environment variables, and CLI flags with layered precedence (defaults < config file < env vars < CLI). Structured logging via `tracing` outputs to stderr at configurable verbosity (`-v` for info, `-vv` for debug). The `--offline` flag restricts operation to cached data only. HTML error page detection prevents caching corrupted downloads. Empty functions (size 0) are handled gracefully.

## Architecture

**Data flow for `disasm` command** (`commands/disasm.rs`):
1. Initialize tracing subscriber (verbosity from `-v`/`-vv`), resolve `Config` (TOML file + env vars + CLI flags), build HTTP client + cache
2. Concurrently fetch `.sym` file (or PDB with `--pdb`) and native binary (`tokio::join!`)
3. Parse `.sym` → `SymFile` (or PDB → `SymFile` via `symbols/pdb.rs`), parse binary → `PeFile`, `ElfFile`, or `MachOFile` (via `BinaryFile` trait)
4. Find target function by name (HashMap lookup) or offset (binary search)
5. Extract code bytes at function's RVA, disassemble via Capstone
6. Annotate: source lines → call targets → inlines → highlight (`disasm/annotate.rs`)
7. Demangle function name, call target names, and inline frame names (`demangle.rs`)
8. Format and print text or JSON output (dispatched via `--format`)

**Graceful degradation**: sym+binary → full disassembly; binary-only → raw disassembly; sym-only → metadata without instructions; neither → error.

**Key modules**:
- `config.rs` — TOML config file parsing (`toml 0.8`); `Config::resolve()` merges defaults < config file < env vars < CLI flags; `_NT_SYMBOL_PATH` parsing for cache dir; config file located via `SYMDIS_CONFIG` env var or platform default (`%APPDATA%\symdis\config.toml` / `~/.config/symdis/config.toml`)
- `cache.rs` — Flat WinDbg-compatible layout (`<root>/<file>/<id>/<file>`); atomic writes via tempfile; negative cache markers with configurable TTL; PDB cache support with separate miss markers (`-pdb.miss`)
- `fetch/` — Orchestrator: Tecken → Microsoft (Windows PE only) → debuginfod (Linux) → Snap Store (Linux) → FTP archive; CAB-compressed downloads (`.dl_`/`.pd_` variants); server URLs parameterized from config; shared `compress_filename`/`decompress_cab` in `fetch/mod.rs`; `is_html_response()` detects corrupted downloads; offline mode skips network after cache miss; cache hit/miss logging via `tracing`; `fetch_pdb_file()` orchestrator for PDB fetch (Tecken → Microsoft) with extended timeout (archive_timeout_seconds) for large PDBs
- `fetch/debuginfod.rs` — debuginfod client for Linux executables; server URLs from config (sourced from `DEBUGINFOD_URLS` env var or config file)
- `fetch/archive.rs` — Mozilla FTP archive client; downloads `.tar.xz` (Linux), `.pkg` (macOS), or `.apk` (Android/Fenix/Focus) build archives; extracts binaries; verifies ELF build IDs and Mach-O UUIDs; archive caching avoids re-downloading for multiple binaries from the same release
- `fetch/snap.rs` — Snap Store client for Ubuntu snap libraries; squashfs extraction via backhand; snap name auto-detection from sym file source paths
- `symbols/breakpad.rs` — Line-by-line parser for `.sym` files; functions and publics sorted by address for binary search; name→index HashMap for exact lookup; `resolve_address` caps PUBLIC symbol distance at 64KB; `get_inline_at` returns active inline frames; `SymFileSummary` for lightweight scanning; `SymFile::from_parts()` constructor for PDB parser
- `symbols/pdb.rs` — PDB → `SymFile` converter via the `pdb` crate; extracts procedures, inline sites (via scope stack tracking), public symbols, and line programs per module; converts PDB section:offset addresses to RVAs via address map; inline code ranges extracted from `BinaryAnnotations` state machine; inlinee names resolved from IPI (ID information) stream; zero-size procedures become PUBLIC symbols; `catch_unwind` around each module to survive `pdb` crate panics (silent panic hook suppresses output)
- `symbols/id_convert.rs` — Debug ID ↔ Build ID conversion (GUID byte-swapping for ELF)
- `binary/pe.rs` — Goblin-based PE parser implementing `BinaryFile` trait; RVA-to-file-offset via section table walk; IAT import resolution for call target annotation
- `binary/elf.rs` — Goblin-based ELF parser implementing `BinaryFile` trait; VA-to-offset via PT_LOAD segments; PLT import mapping for call target annotation
- `binary/macho.rs` — Goblin-based Mach-O parser implementing `BinaryFile` trait; fat (universal) binary support with arch selection; VA-to-offset via segments; export/import resolution; UUID extraction for build verification
- `demangle.rs` — C++/Rust/MSVC symbol demangling via `cpp_demangle` (Itanium ABI), `rustc-demangle`, and `msvc-demangler` (MSVC ABI `?...` symbols); applied at display time, not at parse/storage time; `--no-demangle` opt-out
- `disasm/engine.rs` — Capstone wrapper supporting x86/x86_64/ARM/ARM64 with Intel or ATT syntax; extracts call targets from direct call/jmp instructions
- `disasm/annotate.rs` — Annotation pipeline: source lines, call target resolution (FUNC/PUBLIC/IAT/PLT), inline frame tracking, highlight with mid-instruction range matching
- `output/text.rs` — Text formatter rendering source line comments, call target annotations, inline enter/exit markers, highlight (`==>`) marker; also defines shared `ModuleInfo`, `FunctionInfo`, `DataSource` types (including `BinaryAndPdb` and `PdbOnly` variants)
- `output/json.rs` — JSON formatter with dedicated serde structs; hex-string addresses, hex-encoded bytes, `skip_serializing_if` for optional fields; includes `format_json_error` for structured error output
- `commands/disasm.rs` — Primary command: concurrent sym+binary fetch, parse, find function, disassemble, annotate, format
- `commands/lookup.rs` — Sym-file-only lookup by offset or function name; text and JSON output
- `commands/info.rs` — Lightweight module metadata using `SymFileSummary::scan`; text and JSON output
- `commands/fetch.rs` — Cache pre-warming: concurrent sym+binary fetch with debuginfod and FTP fallback; text and JSON output
- `commands/cache_cmd.rs` — Cache management: `path`, `size` (recursive walk), `clear` (with `--older-than` age filter), `list` (per-module artifacts)

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
- **liblzma 0.4** + **tar 0.4** for Linux `.tar.xz` archive extraction (liblzma replaces xz2 to avoid linking conflict with backhand)
- **backhand 0.24** (`default-features = false`, features `xz`+`lzo`) for squashfs (snap) extraction
- **zip 2** (`default-features = false`, feature `deflate`) for APK extraction (lzma disabled to avoid linking conflict with backhand)
- **quick-xml 0.37** + **cpio_reader 0.1** for macOS `.pkg` (XAR/cpio) archive extraction
- **cpp_demangle 0.4** + **rustc-demangle 0.1** for C++/Rust symbol demangling
- **toml 0.8** for TOML config file parsing
- **tracing 0.1** + **tracing-subscriber 0.3** for structured logging
- **pdb 0.8** for PDB file parsing (pure Rust, no native dependencies)
- **msvc-demangler 0.10** for MSVC-decorated symbol demangling (`?Name@...`)
- **edition = "2021"** (not 2024)

## Reference

- [SPEC.md](SPEC.md) — Full specification (commands, output formats, symbol resolution pipeline, error handling)
- [IMPLEMENTATION.md](IMPLEMENTATION.md) — 16-phase build plan with acceptance criteria per phase
