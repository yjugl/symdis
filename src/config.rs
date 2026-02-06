// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::path::PathBuf;

pub struct Config {
    pub cache_dir: Option<PathBuf>,
    pub symbol_servers: Vec<String>,
    pub debuginfod_urls: Vec<String>,
    pub timeout_seconds: u64,
    pub user_agent: String,
    pub syntax: Syntax,
    pub max_instructions: usize,
    pub format: OutputFormat,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Syntax {
    Intel,
    Att,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            cache_dir: None,
            symbol_servers: vec![
                "https://symbols.mozilla.org/".to_string(),
                "https://msdl.microsoft.com/download/symbols".to_string(),
            ],
            debuginfod_urls: vec!["https://debuginfod.elfutils.org/".to_string()],
            timeout_seconds: 30,
            user_agent: format!("symdis/{}", env!("CARGO_PKG_VERSION")),
            syntax: Syntax::Intel,
            max_instructions: 2000,
            format: OutputFormat::Text,
        }
    }
}
