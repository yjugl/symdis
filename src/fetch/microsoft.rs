use reqwest::Client;

use super::{FetchResult, compress_filename, decompress_cab};

const MS_SYMBOL_SERVER: &str = "https://msdl.microsoft.com/download/symbols";

/// Fetch a PE binary from the Microsoft Symbol Server.
/// Tries uncompressed first, then the CAB-compressed variant.
pub async fn fetch_pe(
    client: &Client,
    pe_name: &str,
    timestamp_size: &str,
) -> FetchResult {
    // Try uncompressed
    let url = format!("{MS_SYMBOL_SERVER}/{pe_name}/{timestamp_size}/{pe_name}");
    match fetch_url(client, &url).await {
        FetchResult::Ok(data) => return FetchResult::Ok(data),
        FetchResult::Error(e) => return FetchResult::Error(e),
        FetchResult::NotFound => {}
    }

    // Try compressed variant (last extension char -> '_')
    let compressed_name = compress_filename(pe_name);
    let url = format!("{MS_SYMBOL_SERVER}/{pe_name}/{timestamp_size}/{compressed_name}");
    match fetch_url(client, &url).await {
        FetchResult::Ok(data) => {
            // Decompress CAB
            match decompress_cab(&data) {
                Ok(decompressed) => FetchResult::Ok(decompressed),
                Err(e) => FetchResult::Error(format!("CAB decompression failed: {e}")),
            }
        }
        FetchResult::NotFound => FetchResult::NotFound,
        FetchResult::Error(e) => FetchResult::Error(e),
    }
}

/// Fetch a PDB file from the Microsoft Symbol Server.
pub async fn fetch_pdb(
    client: &Client,
    pdb_name: &str,
    guid_age: &str,
) -> FetchResult {
    // Try uncompressed
    let url = format!("{MS_SYMBOL_SERVER}/{pdb_name}/{guid_age}/{pdb_name}");
    match fetch_url(client, &url).await {
        FetchResult::Ok(data) => return FetchResult::Ok(data),
        FetchResult::Error(e) => return FetchResult::Error(e),
        FetchResult::NotFound => {}
    }

    // Try compressed variant
    let compressed_name = compress_filename(pdb_name);
    let url = format!("{MS_SYMBOL_SERVER}/{pdb_name}/{guid_age}/{compressed_name}");
    match fetch_url(client, &url).await {
        FetchResult::Ok(data) => {
            match decompress_cab(&data) {
                Ok(decompressed) => FetchResult::Ok(decompressed),
                Err(e) => FetchResult::Error(format!("CAB decompression failed: {e}")),
            }
        }
        FetchResult::NotFound => FetchResult::NotFound,
        FetchResult::Error(e) => FetchResult::Error(e),
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
    fn test_compress_filename() {
        assert_eq!(compress_filename("ntdll.dll"), "ntdll.dl_");
        assert_eq!(compress_filename("ntdll.pdb"), "ntdll.pd_");
        assert_eq!(compress_filename("xul.dll"), "xul.dl_");
    }

    #[test]
    fn test_microsoft_pe_url() {
        let pe_name = "ntdll.dll";
        let timestamp_size = "F9D0B4E4218000";
        let url = format!("{MS_SYMBOL_SERVER}/{pe_name}/{timestamp_size}/{pe_name}");
        assert_eq!(
            url,
            "https://msdl.microsoft.com/download/symbols/ntdll.dll/F9D0B4E4218000/ntdll.dll"
        );
    }

    #[test]
    fn test_microsoft_compressed_url() {
        let pe_name = "ntdll.dll";
        let timestamp_size = "F9D0B4E4218000";
        let compressed = compress_filename(pe_name);
        let url = format!("{MS_SYMBOL_SERVER}/{pe_name}/{timestamp_size}/{compressed}");
        assert_eq!(
            url,
            "https://msdl.microsoft.com/download/symbols/ntdll.dll/F9D0B4E4218000/ntdll.dl_"
        );
    }
}
