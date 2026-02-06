// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Allow dead code during phased development - items will be used in later phases.
#![allow(dead_code)]

mod binary;
mod cache;
mod commands;
mod config;
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
    commands::run(cli).await
}
