// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

pub mod cache_cmd;
pub mod disasm;
pub mod fetch;
pub mod info;
pub mod lookup;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand, ValueEnum};

use crate::config::Config;

const DISASM_LONG_HELP: &str = r#"CRASH REPORT FIELD MAPPING:

  Socorro JSON field     CLI flag            Notes
  ---------------------  ------------------  -------------------------------
  module.debug_file      --debug-file        Required. E.g. "xul.pdb"
  module.debug_id        --debug-id          Required. 33-char hex string
  frame.module_offset    --offset            Hex (with or without 0x prefix)
  frame.function         --function          Exact match; --fuzzy for substr
  frame.module_offset    --highlight-offset  Marks crash address with ==>
  module.filename        --code-file         Improves binary fetch (Windows)
  module.code_id         --code-id           Improves binary fetch (Windows)
  (from release info)    --version           E.g. "128.0.3". FTP fallback
  (from release info)    --channel           release|beta|esr|nightly|aurora
  (from release info)    --build-id          14-digit timestamp (nightly only)
  (snap source paths)    --snap              Snap package name (auto-detected)
  (from product name)    --product           firefox|thunderbird|fenix|focus (default: firefox)

BINARY FETCH CHAIN:

  Sources tried in order for the native binary:
    1. Local cache (instant)
    2. Mozilla Tecken symbol server (code-file + code-id)
    3. Microsoft symbol server (Windows PE only)
    4. debuginfod servers (Linux ELF only, build ID from debug ID)
    5. Snap Store (Linux, when snap detected from sym file or --snap flag)
    6. Mozilla FTP archive (--version + --channel required):
       - Linux: downloads .tar.xz from /pub/firefox/releases/
       - macOS: downloads .pkg from /pub/firefox/releases/
       - Android: downloads .apk from /pub/fenix/releases/ or /pub/focus/releases/
         (requires --product fenix or --product focus; see sections below)

  Providing --code-file and --code-id significantly improves success for
  steps 2-3. Step 5 auto-detects the snap name from source file paths in
  the .sym file (e.g. /build/gnome-42-2204-sdk/parts/...), or use --snap
  to specify it explicitly. Providing --version and --channel enables
  step 6 as a last resort. The .sym file is always fetched from Tecken
  using --debug-file and --debug-id.

FENIX (FIREFOX FOR ANDROID):

  For Android/Fenix crashes, you MUST pass --product fenix explicitly.
  Auto-detection is not possible because Android .sym files report their
  OS as "Linux", not "Android".

  How to recognize a Fenix crash report:
    - The crash report OS field says "Android"
    - The package name is org.mozilla.firefox or org.mozilla.fenix
    - The build architecture is arm or arm64 (sometimes x86/x86_64)

  Required flags for Fenix binary fetch:
    --product fenix --version <VERSION> --channel <CHANNEL>

  Supported channels: release, beta, nightly (no ESR or aurora).
  For nightly, --build-id is also required.

  The binary is extracted from the APK archive at lib/{abi}/libxul.so,
  where the ABI (arm64-v8a, armeabi-v7a, x86_64, x86) is derived from
  the architecture in the .sym file.

FOCUS (FIREFOX FOCUS FOR ANDROID):

  For Firefox Focus crashes, you MUST pass --product focus explicitly.
  Like Fenix, auto-detection is not possible because Android .sym files
  report their OS as "Linux", not "Android".

  How to recognize a Focus crash report:
    - The crash report Product field says "Focus"
    - The crash report OS field says "Android"
    - The build architecture is arm or arm64 (sometimes x86/x86_64)

  Required flags for Focus binary fetch:
    --product focus --version <VERSION> --channel <CHANNEL>

  Supported channels: release, beta, nightly (no ESR or aurora).
  For nightly, --build-id is also required.

  The binary is extracted from the APK archive at lib/{abi}/libxul.so,
  where the ABI (arm64-v8a, armeabi-v7a, x86_64, x86) is derived from
  the architecture in the .sym file.

GRACEFUL DEGRADATION:

  binary + sym file  ->  Full annotated disassembly (source lines, call
                         targets, inline frames, highlight)
  binary only        ->  Raw disassembly (no source annotations)
  sym file only      ->  Function metadata (name, address, size, source)
                         but no disassembly
  neither            ->  Error

EXAMPLES:

  # Windows module -- disassemble by offset, highlight crash address:
  symdis disasm \
      --debug-file xul.pdb \
      --debug-id 44E4EC8C2F41492B9369D6B9A059577C2 \
      --code-file xul.dll --code-id 5CF2591C6859000 \
      --offset 0x1a3f00 --highlight-offset 0x1a3f00

  # Linux module -- with FTP archive fallback:
  symdis disasm \
      --debug-file libxul.so \
      --debug-id 0200CE7B29CF2F761BB067BC519155A00 \
      --code-id 7bce0002cf29762f1bb067bc519155a0cb3f4a31 \
      --version 128.0.3 --channel release \
      --offset 0x3bb5231 --highlight-offset 0x3bb5231

  # macOS module -- fat/universal binary from PKG archive:
  symdis disasm \
      --debug-file XUL \
      --debug-id 697EB30464C83C329FF3A1B119BAC88D0 \
      --code-id 697eb30464c83c329ff3a1b119bac88d \
      --version 128.0.3 --channel release \
      --offset 0x1c019fb

  # Ubuntu snap library (auto-detected from sym file source paths):
  symdis disasm \
      --debug-file libglib-2.0.so.0 \
      --debug-id 8EF7C24A1B02B5A64F56BEA31DCF2B1E0 \
      --code-file libglib-2.0.so.0 \
      --code-id 4ac2f78e021ba6b54f56bea31dcf2b1e19c7f3bc \
      --offset 0x625f6

  # Thunderbird module -- specify --product for non-Firefox products:
  symdis disasm \
      --debug-file libxul.so \
      --debug-id AABBCCDD11223344AABBCCDD11223344A \
      --product thunderbird \
      --version 147.0.1 --channel release \
      --offset 0x6cad38e

  # Fenix (Firefox for Android) -- MUST use --product fenix:
  symdis disasm \
      --debug-file libxul.so \
      --debug-id 9E915B1A91D7345C4FF0753CF13E53280 \
      --code-file libxul.so \
      --code-id 1a5b919ed7915c344ff0753cf13e532814635a84 \
      --product fenix \
      --version 147.0.3 --channel release \
      --offset 0x03fc39d4 --highlight-offset 0x03fc39d4

  # Focus (Firefox Focus for Android) -- MUST use --product focus:
  symdis disasm \
      --debug-file libxul.so \
      --debug-id AABBCCDD11223344AABBCCDD11223344A \
      --product focus \
      --version 134.0.2 --channel release \
      --offset 0x01234567

  # Search by function name (substring match):
  symdis disasm \
      --debug-file xul.pdb \
      --debug-id 44E4EC8C2F41492B9369D6B9A059577C2 \
      --function SetAttribute --fuzzy

  # JSON output for structured parsing:
  symdis disasm \
      --debug-file ntdll.pdb \
      --debug-id 1EB9FACB04EA273BB24BA52C8B8D336A1 \
      --function NtCreateFile --format json

TIPS:

  - Use --format json for machine-parseable output.
  - Use --highlight-offset with the crash address (frame.module_offset)
    to mark the faulting instruction with ==> in text output or
    "highlighted": true in JSON output.
  - --offset finds the containing function and disassembles it entirely;
    combine with --highlight-offset to pinpoint the specific instruction.
  - Use 'symdis info' first to check if sym/binary files are available.
  - Use 'symdis lookup --offset 0x...' for quick symbol resolution
    without full disassembly.
  - For nightly builds, --build-id is the 14-digit build timestamp
    (YYYYMMDDHHmmSS) from the crash report's build_id field.
  - For Thunderbird crashes, add --product thunderbird to fetch
    binaries from the Thunderbird FTP archive instead of Firefox.
  - For Fenix (Firefox for Android) crashes, --product fenix is
    REQUIRED. For Focus (Firefox Focus), use --product focus.
    Neither can be auto-detected because Android .sym files report
    OS as "Linux". See the FENIX and FOCUS sections above for details."#;

const LOOKUP_LONG_HELP: &str = r#"CRASH REPORT FIELD MAPPING:

  Socorro JSON field     CLI flag        Notes
  ---------------------  --------------  --------------------------------
  module.debug_file      --debug-file    Required. E.g. "xul.pdb"
  module.debug_id        --debug-id      Required. 33-char hex string
  frame.module_offset    --offset        Hex (with or without 0x prefix)
  frame.function         --function      Exact match; --fuzzy for substr

  Operates on the .sym file only (no binary needed). Resolves an offset
  to the containing function name, or a function name to its address and
  size. Useful for quick symbol lookups without full disassembly.

EXAMPLES:

  # Resolve an offset to a symbol name:
  symdis lookup \
      --debug-file xul.pdb \
      --debug-id 44E4EC8C2F41492B9369D6B9A059577C2 \
      --offset 0x1a3f00

  # Find a function's address by name (substring match):
  symdis lookup \
      --debug-file xul.pdb \
      --debug-id 44E4EC8C2F41492B9369D6B9A059577C2 \
      --function SetAttribute --fuzzy"#;

const FETCH_LONG_HELP: &str = r#"CRASH REPORT FIELD MAPPING:

  Socorro JSON field     CLI flag        Notes
  ---------------------  --------------  --------------------------------
  module.debug_file      --debug-file    Required. E.g. "xul.pdb"
  module.debug_id        --debug-id      Required. 33-char hex string
  module.filename        --code-file     Improves binary fetch (Windows)
  module.code_id         --code-id       Improves binary fetch (Windows)
  (from release info)    --version       E.g. "128.0.3". FTP fallback
  (from release info)    --channel       release|beta|esr|nightly|aurora
  (from release info)    --build-id      14-digit timestamp (nightly only)
  (snap source paths)    --snap          Snap package name (explicit only)
  (from product name)    --product       firefox|thunderbird|fenix|focus (default: firefox)

  Pre-fetches the .sym file and native binary into the local cache so
  that subsequent disasm calls are instant cache hits. Useful when you
  plan to disassemble multiple functions from the same module.

  Binary fetch chain: cache → Tecken → Microsoft (Windows) → debuginfod
  (Linux) → Snap Store (Linux, --snap) → FTP archive (--version + --channel).

  For Android crashes, --product fenix or --product focus is REQUIRED
  (it cannot be auto-detected because Android .sym files report OS as
  "Linux"). Binary fetch downloads the APK from Mozilla's FTP server
  and extracts the native library from lib/{abi}/ inside the APK.

  Note: snap auto-detection from sym file source paths is only available
  in the disasm command. For fetch, use --snap explicitly.

EXAMPLES:

  # Pre-fetch a Windows module:
  symdis fetch \
      --debug-file xul.pdb \
      --debug-id 44E4EC8C2F41492B9369D6B9A059577C2 \
      --code-file xul.dll --code-id 5CF2591C6859000

  # Pre-fetch a Linux module with FTP archive fallback:
  symdis fetch \
      --debug-file libxul.so \
      --debug-id 0200CE7B29CF2F761BB067BC519155A00 \
      --version 128.0.3 --channel release

  # Pre-fetch a Fenix (Android) module:
  symdis fetch \
      --debug-file libxul.so \
      --debug-id 9E915B1A91D7345C4FF0753CF13E53280 \
      --product fenix \
      --version 147.0.3 --channel release

  # Pre-fetch a Focus (Android) module:
  symdis fetch \
      --debug-file libxul.so \
      --debug-id AABBCCDD11223344AABBCCDD11223344A \
      --product focus \
      --version 134.0.2 --channel release

  # Pre-fetch a snap library:
  symdis fetch \
      --debug-file libglib-2.0.so.0 \
      --debug-id 8EF7C24A1B02B5A64F56BEA31DCF2B1E0 \
      --snap gnome-42-2204-sdk

TIPS:

  - Run 'symdis fetch' once before a series of 'symdis disasm' calls
    on the same module to avoid redundant network requests.
  - Use -v to see cache hit/miss details on stderr."#;

const INFO_LONG_HELP: &str = r#"CRASH REPORT FIELD MAPPING:

  Socorro JSON field     CLI flag        Notes
  ---------------------  --------------  --------------------------------
  module.debug_file      --debug-file    Required. E.g. "xul.pdb"
  module.debug_id        --debug-id      Required. 33-char hex string
  module.filename        --code-file     Optional. For binary availability
  module.code_id         --code-id       Optional. For binary availability

  Shows module metadata from the .sym file: module name, debug ID, OS,
  architecture, function count, and whether the binary is available.

EXAMPLES:

  # Check module metadata and sym/binary availability:
  symdis info \
      --debug-file xul.pdb \
      --debug-id 44E4EC8C2F41492B9369D6B9A059577C2 \
      --code-file xul.dll --code-id 5CF2591C6859000

TIPS:

  - Run 'symdis info' before 'symdis disasm' to check whether the sym
    file and binary are available before attempting full disassembly."#;

#[derive(Parser)]
#[command(
    name = "symdis",
    version,
    about = "Symbolic disassembler for Mozilla crash report analysis",
    long_about = "Symbolic disassembler for Mozilla crash report analysis.\n\n\
        Designed for AI agents analyzing Mozilla crash reports. Given a module's \
        debug identifiers and a function name or offset from a crash report, \
        symdis fetches symbols and binaries from Mozilla/Microsoft symbol \
        servers and produces annotated disassembly with source lines, call \
        targets, and inline frames.\n\n\
        Subcommands:\n  \
        disasm   Disassemble a function (primary command)\n  \
        lookup   Resolve offset → symbol or symbol → address (sym file only)\n  \
        info     Show module metadata (sym file availability, function count)\n  \
        fetch    Pre-fetch symbols and binary into cache\n  \
        cache    Manage the local cache (path, size, clear, list)"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Cache directory path
    #[arg(long, global = true)]
    pub cache_dir: Option<String>,

    /// Output format
    #[arg(long, global = true, default_value = "text")]
    pub format: FormatArg,

    /// Disable C++/Rust symbol demangling
    #[arg(long, global = true)]
    pub no_demangle: bool,

    /// Verbose output (-v info, -vv debug)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Skip network requests; use only cached data
    #[arg(long, global = true)]
    pub offline: bool,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum FormatArg {
    Text,
    Json,
}

#[derive(Subcommand)]
pub enum Command {
    /// Disassemble a function from a module
    Disasm(DisasmArgs),
    /// Resolve a module offset to a symbol name, or a symbol name to an address
    Lookup(LookupArgs),
    /// Show module metadata
    Info(InfoArgs),
    /// Pre-fetch symbols and binary for a module
    Fetch(FetchArgs),
    /// Manage the local cache
    Cache(CacheArgs),
}

#[derive(Parser)]
#[command(after_long_help = DISASM_LONG_HELP)]
pub struct DisasmArgs {
    /// Debug file name (e.g., xul.pdb, libxul.so)
    #[arg(long)]
    pub debug_file: String,

    /// Debug identifier (33-character hex string)
    #[arg(long)]
    pub debug_id: String,

    /// Function name to disassemble
    #[arg(long, conflicts_with = "offset")]
    pub function: Option<String>,

    /// RVA / module offset (hex, with or without 0x prefix)
    #[arg(long, conflicts_with = "function")]
    pub offset: Option<String>,

    /// Disassembly syntax
    #[arg(long, default_value = "intel")]
    pub syntax: SyntaxArg,

    /// Mark a specific offset in the output (auto-extends --max-instructions if needed)
    #[arg(long)]
    pub highlight_offset: Option<String>,

    /// Enable substring/fuzzy matching for --function
    #[arg(long)]
    pub fuzzy: bool,

    /// Safety limit on output size (auto-extended when --highlight-offset falls beyond it)
    #[arg(long, default_value = "2000")]
    pub max_instructions: usize,

    /// Code file name (e.g., xul.dll)
    #[arg(long)]
    pub code_file: Option<String>,

    /// Code identifier
    #[arg(long)]
    pub code_id: Option<String>,

    /// Product version (e.g., "147.0.3") for FTP archive fallback
    #[arg(long)]
    pub version: Option<String>,

    /// Release channel (release, beta, nightly, esr, aurora) for FTP archive fallback
    #[arg(long)]
    pub channel: Option<String>,

    /// Build ID timestamp (required for nightly channel only)
    #[arg(long)]
    pub build_id: Option<String>,

    /// Snap package name (auto-detected from sym file source paths if not specified)
    #[arg(long)]
    pub snap: Option<String>,

    /// Mozilla product: firefox (default), thunderbird, fenix, or focus.
    /// For Android crashes, you MUST specify --product fenix or --product focus.
    /// It cannot be auto-detected (Android .sym files report OS as "Linux").
    #[arg(long, default_value = "firefox")]
    pub product: String,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum SyntaxArg {
    Intel,
    Att,
}

#[derive(Parser)]
#[command(after_long_help = LOOKUP_LONG_HELP)]
pub struct LookupArgs {
    /// Debug file name
    #[arg(long)]
    pub debug_file: String,

    /// Debug identifier
    #[arg(long)]
    pub debug_id: String,

    /// Function name
    #[arg(long, conflicts_with = "offset")]
    pub function: Option<String>,

    /// RVA / module offset
    #[arg(long, conflicts_with = "function")]
    pub offset: Option<String>,

    /// Enable substring/fuzzy matching for --function
    #[arg(long)]
    pub fuzzy: bool,
}

#[derive(Parser)]
#[command(after_long_help = INFO_LONG_HELP)]
pub struct InfoArgs {
    /// Debug file name
    #[arg(long)]
    pub debug_file: String,

    /// Debug identifier
    #[arg(long)]
    pub debug_id: String,

    /// Code file name
    #[arg(long)]
    pub code_file: Option<String>,

    /// Code identifier
    #[arg(long)]
    pub code_id: Option<String>,

    /// Product version (e.g., "147.0.3") for FTP archive fallback
    #[arg(long)]
    pub version: Option<String>,

    /// Release channel (release, beta, nightly, esr, aurora) for FTP archive fallback
    #[arg(long)]
    pub channel: Option<String>,

    /// Build ID timestamp (required for nightly channel only)
    #[arg(long)]
    pub build_id: Option<String>,

    /// Mozilla product: firefox (default), thunderbird, or fenix.
    /// For Android/Fenix crashes, you MUST specify --product fenix.
    #[arg(long, default_value = "firefox")]
    pub product: String,
}

#[derive(Parser)]
#[command(after_long_help = FETCH_LONG_HELP)]
pub struct FetchArgs {
    /// Debug file name
    #[arg(long)]
    pub debug_file: String,

    /// Debug identifier
    #[arg(long)]
    pub debug_id: String,

    /// Code file name
    #[arg(long)]
    pub code_file: Option<String>,

    /// Code identifier
    #[arg(long)]
    pub code_id: Option<String>,

    /// Product version (e.g., "147.0.3") for FTP archive fallback
    #[arg(long)]
    pub version: Option<String>,

    /// Release channel (release, beta, nightly, esr, aurora) for FTP archive fallback
    #[arg(long)]
    pub channel: Option<String>,

    /// Build ID timestamp (required for nightly channel only)
    #[arg(long)]
    pub build_id: Option<String>,

    /// Snap package name (not auto-detected; use --snap explicitly for fetch)
    #[arg(long)]
    pub snap: Option<String>,

    /// Mozilla product: firefox (default), thunderbird, or fenix.
    /// For Android/Fenix crashes, you MUST specify --product fenix.
    #[arg(long, default_value = "firefox")]
    pub product: String,
}

#[derive(Parser)]
pub struct CacheArgs {
    #[command(subcommand)]
    pub action: CacheAction,
}

#[derive(Subcommand)]
pub enum CacheAction {
    /// Print the cache directory path
    Path,
    /// Print the total size of cached files
    Size,
    /// Delete cached files
    Clear {
        /// Delete files older than N days
        #[arg(long)]
        older_than: Option<u64>,
    },
    /// List cached artifacts for a specific module
    List {
        /// Debug file name to filter by
        #[arg(long)]
        debug_file: String,
    },
}

pub async fn run(cli: Cli) -> Result<()> {
    let config = Config::resolve(&cli)?;

    match cli.command {
        Command::Disasm(ref args) => {
            if args.function.is_none() && args.offset.is_none() {
                bail!("Either --function or --offset must be specified");
            }
            disasm::run(args, &config).await
        }
        Command::Lookup(ref args) => {
            if args.function.is_none() && args.offset.is_none() {
                bail!("Either --function or --offset must be specified");
            }
            lookup::run(args, &config).await
        }
        Command::Info(ref args) => {
            info::run(args, &config).await
        }
        Command::Fetch(ref args) => fetch::run(args, &config).await,
        Command::Cache(args) => cache_cmd::run(args, &config),
    }
}
