// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Allow dead code during phased development - items will be used in later phases.
#![allow(dead_code)]

mod binary;
mod cache;
mod commands;
mod config;
mod demangle;
mod disasm;
mod fetch;
mod output;
mod symbols;

use anyhow::Result;
use clap::Parser;
use commands::Cli;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let level = match cli.verbose {
        0 => tracing::Level::WARN,
        1 => tracing::Level::INFO,
        _ => tracing::Level::DEBUG,
    };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .with_writer(std::io::stderr)
        .without_time()
        .init();

    commands::run(cli).await
}
