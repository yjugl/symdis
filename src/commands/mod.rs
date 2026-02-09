// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

pub mod cache_cmd;
pub mod disasm;
pub mod fetch;
pub mod frames;
pub mod info;
pub mod lookup;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "symdis", version, about = "Symbolic disassembler for Mozilla crash report analysis")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Cache directory path
    #[arg(long, global = true)]
    pub cache_dir: Option<String>,

    /// Output format
    #[arg(long, global = true, default_value = "text")]
    pub format: FormatArg,

    /// Verbose output (-v info, -vv debug)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,
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
    /// Process multiple stack frames from a crash report
    Frames(FramesArgs),
    /// Manage the local cache
    Cache(CacheArgs),
}

#[derive(Parser)]
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

    /// Mark a specific offset in the output
    #[arg(long)]
    pub highlight_offset: Option<String>,

    /// Enable substring/fuzzy matching for --function
    #[arg(long)]
    pub fuzzy: bool,

    /// Safety limit on output size
    #[arg(long, default_value = "2000")]
    pub max_instructions: usize,

    /// Code file name (e.g., xul.dll)
    #[arg(long)]
    pub code_file: Option<String>,

    /// Code identifier
    #[arg(long)]
    pub code_id: Option<String>,

    /// Firefox version (e.g., "147.0.3") for FTP archive fallback
    #[arg(long)]
    pub version: Option<String>,

    /// Firefox release channel (release, beta, nightly, esr) for FTP archive fallback
    #[arg(long)]
    pub channel: Option<String>,

    /// Firefox build ID timestamp (required for nightly channel only)
    #[arg(long)]
    pub build_id: Option<String>,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum SyntaxArg {
    Intel,
    Att,
}

#[derive(Parser)]
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

    /// Firefox version (e.g., "147.0.3") for FTP archive fallback
    #[arg(long)]
    pub version: Option<String>,

    /// Firefox release channel (release, beta, nightly, esr) for FTP archive fallback
    #[arg(long)]
    pub channel: Option<String>,

    /// Firefox build ID timestamp (required for nightly channel only)
    #[arg(long)]
    pub build_id: Option<String>,
}

#[derive(Parser)]
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

    /// Firefox version (e.g., "147.0.3") for FTP archive fallback
    #[arg(long)]
    pub version: Option<String>,

    /// Firefox release channel (release, beta, nightly, esr) for FTP archive fallback
    #[arg(long)]
    pub channel: Option<String>,

    /// Firefox build ID timestamp (required for nightly channel only)
    #[arg(long)]
    pub build_id: Option<String>,
}

#[derive(Parser)]
pub struct FramesArgs {
    /// Path to a processed crash report JSON file
    #[arg(long, conflicts_with = "crash_id")]
    pub crash_report: Option<String>,

    /// Socorro crash ID
    #[arg(long, conflicts_with = "crash_report")]
    pub crash_id: Option<String>,

    /// Which thread: "crashing" or a thread index
    #[arg(long, default_value = "crashing")]
    pub thread: String,

    /// Which frames: "all", a single index, or a range "N-M"
    #[arg(long, default_value = "0-9")]
    pub frames: String,
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
    match cli.command {
        Command::Disasm(ref args) => {
            if args.function.is_none() && args.offset.is_none() {
                bail!("Either --function or --offset must be specified");
            }
            disasm::run(args, &cli).await
        }
        Command::Lookup(ref args) => {
            if args.function.is_none() && args.offset.is_none() {
                bail!("Either --function or --offset must be specified");
            }
            lookup::run(args, &cli).await
        }
        Command::Info(ref args) => {
            info::run(args, &cli).await
        }
        Command::Fetch(_args) => {
            eprintln!("fetch: not yet implemented");
            Ok(())
        }
        Command::Frames(_args) => {
            eprintln!("frames: not yet implemented");
            Ok(())
        }
        Command::Cache(args) => cache_cmd::run(args),
    }
}
