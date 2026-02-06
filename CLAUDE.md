# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
cargo build                          # Build
cargo clippy -- -D warnings          # Lint (must pass with zero warnings)
cargo test                           # Run all 64 unit tests
cargo test symbols::breakpad         # Run tests in a specific module
cargo test test_rva_to_offset        # Run a single test by name
cargo run -- disasm --help           # Run CLI with args
```

## Project Status

Phases 0-8 of the [implementation plan](IMPLEMENTATION.md) are complete. The `disasm` command works end-to-end: fetch sym+binary from symbol servers, find a function, disassemble, annotate with source lines/call targets/inlines/highlight, and print text or JSON output (`--format text|json`). Remaining commands (`lookup`, `info`, `fetch`, `frames`) and features (ELF/Mach-O, demangling) are stubbed but not yet implemented.

`#![allow(dead_code)]` is set in `main.rs` because many pub items are defined ahead of use for later phases. Remove this once all phases are complete.

## Architecture

**Data flow for `disasm` command** (`commands/disasm.rs`):
1. Build HTTP client + resolve cache directory
2. Concurrently fetch `.sym` file and native binary (`tokio::join!`)
3. Parse `.sym` → `SymFile`, parse binary → `PeFile` (via `BinaryFile` trait)
4. Find target function by name (HashMap lookup) or offset (binary search)
5. Extract code bytes at function's RVA, disassemble via Capstone
6. Annotate: source lines → call targets → inlines → highlight (`disasm/annotate.rs`)
7. Format and print text or JSON output (dispatched via `--format`)

**Graceful degradation**: sym+binary → full disassembly; binary-only → raw disassembly; sym-only → metadata without instructions; neither → error.

**Key modules**:
- `cache.rs` — Flat WinDbg-compatible layout (`<root>/<file>/<id>/<file>`); atomic writes via tempfile; negative cache markers with 24h TTL; `_NT_SYMBOL_PATH` integration
- `fetch/` — Orchestrator tries Tecken then Microsoft symbol server; both clients handle CAB-compressed downloads (`.dl_`/`.pd_` variants); shared `compress_filename`/`decompress_cab` in `fetch/mod.rs`
- `symbols/breakpad.rs` — Line-by-line parser for `.sym` files; functions and publics sorted by address for binary search; name→index HashMap for exact lookup; `resolve_address` caps PUBLIC symbol distance at 64KB; `get_inline_at` returns active inline frames
- `binary/pe.rs` — Goblin-based PE parser implementing `BinaryFile` trait; RVA-to-file-offset via section table walk; IAT import resolution for call target annotation
- `disasm/engine.rs` — Capstone wrapper supporting x86/x86_64/ARM/ARM64 with Intel or ATT syntax; extracts call targets from direct call/jmp instructions
- `disasm/annotate.rs` — Annotation pipeline: source lines, call target resolution (FUNC/PUBLIC/IAT), inline frame tracking, highlight with mid-instruction range matching
- `output/text.rs` — Text formatter rendering source line comments, call target annotations, inline enter/exit markers, highlight (`==>`) marker; also defines shared `ModuleInfo`, `FunctionInfo`, `DataSource` types
- `output/json.rs` — JSON formatter with dedicated serde structs; hex-string addresses, hex-encoded bytes, `skip_serializing_if` for optional fields; includes `format_json_error` for structured error output

## Key Conventions

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
- **edition = "2021"** (not 2024)

## Reference

- [SPEC.md](SPEC.md) — Full specification (commands, output formats, symbol resolution pipeline, error handling)
- [IMPLEMENTATION.md](IMPLEMENTATION.md) — 16-phase build plan with acceptance criteria per phase
