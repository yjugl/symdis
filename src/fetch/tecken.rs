use reqwest::Client;

use super::{FetchResult, sym_filename, compress_filename, decompress_cab};

const TECKEN_BASE: &str = "https://symbols.mozilla.org";

/// Fetch a .sym file from Mozilla Tecken.
/// URL pattern: <base>/<debug_file>/<debug_id>/<stem>.sym
pub async fn fetch_sym(
    client: &Client,
    debug_file: &str,
    debug_id: &str,
) -> FetchResult {
    let sym_name = sym_filename(debug_file);
    let url = format!("{TECKEN_BASE}/{debug_file}/{debug_id}/{sym_name}");
    fetch_url(client, &url).await
}

/// Fetch a binary from Tecken using code-file/code-id.
/// Tries uncompressed first, then the CAB-compressed variant.
/// URL patterns:
///   <base>/<code_file>/<code_id>/<code_file>
///   <base>/<code_file>/<code_id>/<code_file_compressed>  (CAB)
pub async fn fetch_binary_by_code_id(
    client: &Client,
    code_file: &str,
    code_id: &str,
) -> FetchResult {
    // Try uncompressed
    let url = format!("{TECKEN_BASE}/{code_file}/{code_id}/{code_file}");
    match fetch_url(client, &url).await {
        FetchResult::Ok(data) => return FetchResult::Ok(data),
        FetchResult::Error(e) => return FetchResult::Error(e),
        FetchResult::NotFound => {}
    }

    // Try compressed variant (last extension char -> '_')
    let compressed_name = compress_filename(code_file);
    let url = format!("{TECKEN_BASE}/{code_file}/{code_id}/{compressed_name}");
    match fetch_url(client, &url).await {
        FetchResult::Ok(data) => match decompress_cab(&data) {
            Ok(decompressed) => FetchResult::Ok(decompressed),
            Err(e) => FetchResult::Error(format!("CAB decompression failed: {e}")),
        },
        other => other,
    }
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
    fn test_tecken_sym_url() {
        // Verify the URL construction logic
        let debug_file = "xul.pdb";
        let debug_id = "44E4EC8C2F41492B9369D6B9A059577C2";
        let sym_name = sym_filename(debug_file);
        let url = format!("{TECKEN_BASE}/{debug_file}/{debug_id}/{sym_name}");
        assert_eq!(
            url,
            "https://symbols.mozilla.org/xul.pdb/44E4EC8C2F41492B9369D6B9A059577C2/xul.sym"
        );
    }

    #[test]
    fn test_tecken_binary_url() {
        let code_file = "xul.dll";
        let code_id = "5CF2591C6859000";
        let url = format!("{TECKEN_BASE}/{code_file}/{code_id}/{code_file}");
        assert_eq!(
            url,
            "https://symbols.mozilla.org/xul.dll/5CF2591C6859000/xul.dll"
        );
    }
}
