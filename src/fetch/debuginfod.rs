// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use reqwest::Client;
use tracing::debug;

use super::FetchResult;

/// Fetch an ELF executable from debuginfod servers concurrently.
///
/// URL pattern: `<server>/buildid/<build_id>/executable`
///
/// Fires requests to all servers simultaneously and returns as soon as the
/// first server responds with data. Remaining requests are cancelled.
pub async fn fetch_executable(
    client: &Client,
    build_id: &str,
    servers: &[String],
) -> FetchResult {
    let mut set = tokio::task::JoinSet::new();

    for server in servers {
        let client = client.clone();
        let base = server.trim_end_matches('/').to_string();
        let url = format!("{base}/buildid/{build_id}/executable");
        debug!("trying debuginfod: {url}");
        set.spawn(async move { fetch_url(&client, &url).await });
    }

    while let Some(result) = set.join_next().await {
        if let Ok(FetchResult::Ok(data)) = result {
            set.abort_all();
            return FetchResult::Ok(data);
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
