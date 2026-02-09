// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use reqwest::Client;

use super::FetchResult;

pub const DEFAULT_DEBUGINFOD_URL: &str = "https://debuginfod.elfutils.org";

/// Fetch an ELF executable from debuginfod servers.
///
/// URL pattern: `<server>/buildid/<build_id>/executable`
///
/// Tries each server in order until one succeeds.
pub async fn fetch_executable(
    client: &Client,
    build_id: &str,
    servers: &[String],
) -> FetchResult {
    for server in servers {
        let base = server.trim_end_matches('/');
        let url = format!("{base}/buildid/{build_id}/executable");
        match fetch_url(client, &url).await {
            FetchResult::Ok(data) => return FetchResult::Ok(data),
            FetchResult::Error(e) => {
                eprintln!("warning: debuginfod {base}: {e}");
            }
            FetchResult::NotFound => {}
        }
    }
    FetchResult::NotFound
}

/// Fetch debug info from debuginfod servers.
///
/// URL pattern: `<server>/buildid/<build_id>/debuginfo`
pub async fn fetch_debuginfo(
    client: &Client,
    build_id: &str,
    servers: &[String],
) -> FetchResult {
    for server in servers {
        let base = server.trim_end_matches('/');
        let url = format!("{base}/buildid/{build_id}/debuginfo");
        match fetch_url(client, &url).await {
            FetchResult::Ok(data) => return FetchResult::Ok(data),
            FetchResult::Error(e) => {
                eprintln!("warning: debuginfod {base}: {e}");
            }
            FetchResult::NotFound => {}
        }
    }
    FetchResult::NotFound
}

async fn fetch_url(client: &Client, url: &str) -> FetchResult {
    let response = match client.get(url).send().await {
        Ok(r) => r,
        Err(e) => return FetchResult::Error(format!("request failed: {e}")),
    };

    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return FetchResult::NotFound;
    }
    if !status.is_success() {
        return FetchResult::Error(format!("HTTP {status} from {url}"));
    }

    match response.bytes().await {
        Ok(bytes) => FetchResult::Ok(bytes.to_vec()),
        Err(e) => FetchResult::Error(format!("reading response body: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_debuginfod_url() {
        assert_eq!(DEFAULT_DEBUGINFOD_URL, "https://debuginfod.elfutils.org");
    }

    #[test]
    fn test_executable_url_format() {
        let server = "https://debuginfod.elfutils.org";
        let build_id = "b7dc60e91588d8a54c4c44205044422eaabbccdd";
        let url = format!("{server}/buildid/{build_id}/executable");
        assert_eq!(
            url,
            "https://debuginfod.elfutils.org/buildid/b7dc60e91588d8a54c4c44205044422eaabbccdd/executable"
        );
    }

    #[test]
    fn test_debuginfo_url_format() {
        let server = "https://debuginfod.elfutils.org";
        let build_id = "b7dc60e91588d8a54c4c44205044422eaabbccdd";
        let url = format!("{server}/buildid/{build_id}/debuginfo");
        assert_eq!(
            url,
            "https://debuginfod.elfutils.org/buildid/b7dc60e91588d8a54c4c44205044422eaabbccdd/debuginfo"
        );
    }
}
