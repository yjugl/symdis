// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use anyhow::Result;

use super::{CacheArgs, CacheAction};
use crate::cache::Cache;

pub fn run(args: CacheArgs) -> Result<()> {
    let cache = Cache::new(None)?;
    match args.action {
        CacheAction::Path => {
            println!("{}", cache.root().display());
            Ok(())
        }
        CacheAction::Size => {
            eprintln!("cache size: not yet implemented");
            Ok(())
        }
        CacheAction::Clear { older_than: _ } => {
            eprintln!("cache clear: not yet implemented");
            Ok(())
        }
        CacheAction::List { debug_file: _ } => {
            eprintln!("cache list: not yet implemented");
            Ok(())
        }
    }
}
