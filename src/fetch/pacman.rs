// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::io::Read;

use anyhow::{bail, Context, Result};
use reqwest::Client;
use tracing::{debug, info};

use super::apt::{extract_from_tar, extract_hostname};

/// Default Arch Linux mirror (GeoIP-based).
const DEFAULT_PACMAN_MIRROR: &str = "https://geo.mirror.pkgbuild.com";

/// Default repositories to search.
const DEFAULT_REPOS: &[&str] = &["core", "extra", "multilib"];

/// Parameters needed to locate a package in pacman repos.
pub struct PacmanLocator {
    /// Explicit package name, or None for auto-detect via PROVIDES.
    pub package: Option<String>,
    /// Mirror base URL.
    pub mirror: String,
    /// Repositories to search.
    pub repos: Vec<String>,
    /// Pacman architecture (e.g., "x86_64").
    pub architecture: String,
}

/// Parsed package description from the repo database.
struct PkgDesc {
    name: String,
    version: String,
    filename: String,
    provides: Vec<String>,
}

/// Map Breakpad .sym architecture to pacman architecture.
/// Currently only x86_64 is supported (Arch official repos).
pub fn pacman_architecture(sym_arch: &str) -> Option<&'static str> {
    match sym_arch {
        "x86_64" => Some("x86_64"),
        _ => None,
    }
}

/// Build a PacmanLocator from CLI args.
pub fn build_locator(
    package: Option<String>,
    mirror: Option<&str>,
    sym_arch: &str,
) -> Result<PacmanLocator> {
    let architecture = match pacman_architecture(sym_arch) {
        Some(arch) => arch.to_string(),
        None => bail!(
            "pacman backend only supports x86_64 (got '{}'). \
             Arch Linux ARM is a separate project with different repositories.",
            sym_arch
        ),
    };

    Ok(PacmanLocator {
        package,
        mirror: mirror.unwrap_or(DEFAULT_PACMAN_MIRROR).to_string(),
        repos: DEFAULT_REPOS.iter().map(|s| s.to_string()).collect(),
        architecture,
    })
}

/// Fetch and search the pacman repo database to find a package.
///
/// If `locator.package` is Some, look up by name. Otherwise, search
/// PROVIDES entries for a match against `code_file` (soname matching).
pub async fn resolve_package(
    client: &Client,
    cache: &crate::cache::Cache,
    locator: &PacmanLocator,
    code_file: &str,
) -> Result<(String, String, String)> {
    // Collect all packages across repos for multi-pass matching
    let mut all_packages: Vec<(String, Vec<PkgDesc>)> = Vec::new();

    for repo in &locator.repos {
        let db_url = format!(
            "{}/{}/os/{}/{}.db.tar.gz",
            locator.mirror, repo, locator.architecture, repo
        );

        let db_data = fetch_repo_db(client, cache, &db_url, repo, &locator.architecture).await?;
        let packages = parse_db_tar(&db_data)?;
        all_packages.push((repo.clone(), packages));
    }

    // Pass 1: explicit name lookup
    if let Some(ref pkg_name) = locator.package {
        for (repo, packages) in &all_packages {
            if let Some(pkg) = packages.iter().find(|p| p.name == *pkg_name) {
                let pkg_url = format!(
                    "{}/{}/os/{}/{}",
                    locator.mirror, repo, locator.architecture, pkg.filename
                );
                info!("found package {} {} in {repo}", pkg.name, pkg.version);
                return Ok((pkg.name.clone(), pkg_url, pkg.filename.clone()));
            }
        }
        bail!(
            "package '{}' not found in pacman repos (searched: {})",
            pkg_name,
            locator.repos.join(", ")
        );
    }

    // Pass 2: PROVIDES matching (soname)
    for (repo, packages) in &all_packages {
        if let Some(pkg) = find_package_by_provides(packages, code_file) {
            let pkg_url = format!(
                "{}/{}/os/{}/{}",
                locator.mirror, repo, locator.architecture, pkg.filename
            );
            info!(
                "found package {} {} in {repo} (provides match for {})",
                pkg.name, pkg.version, code_file
            );
            return Ok((pkg.name.clone(), pkg_url, pkg.filename.clone()));
        }
    }

    // Pass 3: name-based fallback — derive package name from binary filename
    // e.g., libX11.so.6 → libx11, libdrm.so.2 → libdrm
    if let Some(derived) = derive_package_name(code_file) {
        for (repo, packages) in &all_packages {
            if let Some(pkg) = packages.iter().find(|p| p.name == derived) {
                let pkg_url = format!(
                    "{}/{}/os/{}/{}",
                    locator.mirror, repo, locator.architecture, pkg.filename
                );
                info!(
                    "found package {} {} in {repo} (name match from {})",
                    pkg.name, pkg.version, code_file
                );
                return Ok((pkg.name.clone(), pkg_url, pkg.filename.clone()));
            }
        }
    }

    // Auto-detect failed — build a helpful error message
    let hint = derive_package_name(code_file)
        .map(|name| {
            format!(
                "\nTry: --pacman <package_name> (e.g., --pacman {} if you know the package)",
                name
            )
        })
        .unwrap_or_else(|| {
            "\nTry: --pacman <package_name> to specify the package explicitly".to_string()
        });
    bail!(
        "no pacman package provides '{}' (searched: {}){}",
        code_file,
        locator.repos.join(", "),
        hint
    )
}

/// Download a package and extract the target binary.
pub async fn download_and_extract(
    client: &Client,
    cache: &crate::cache::Cache,
    pkg_url: &str,
    pkg_filename: &str,
    code_file: &str,
    locator: &PacmanLocator,
) -> Result<Vec<u8>> {
    // Check if .pkg.tar.zst is already cached
    let (cache_file, cache_id) = pkg_cache_key(pkg_url, locator);
    let pkg_key = crate::cache::BinaryCacheKey {
        code_file: cache_file.clone(),
        code_id: cache_id,
        filename: cache_file,
    };

    let pkg_data = match cache.get_binary(&pkg_key) {
        crate::cache::CacheResult::Hit(path) => {
            info!("using cached package: {}", path.display());
            std::fs::read(&path)
                .with_context(|| format!("reading cached package: {}", path.display()))?
        }
        _ => {
            info!("downloading package: {pkg_filename}");
            let response = client
                .get(pkg_url)
                .send()
                .await
                .context("downloading pacman package")?;

            let status = response.status();
            if status == reqwest::StatusCode::NOT_FOUND {
                bail!("package not found: {pkg_url} (HTTP 404)");
            }
            if !status.is_success() {
                bail!("package download failed: {pkg_url} (HTTP {status})");
            }

            let data = response
                .bytes()
                .await
                .context("reading package body")?
                .to_vec();

            info!(
                "downloaded package: {} ({:.1} MB)",
                pkg_filename,
                data.len() as f64 / 1_048_576.0
            );

            // Cache the package
            cache.store_binary(&pkg_key, &data)?;
            data
        }
    };

    // Decompress .pkg.tar.zst → tar
    let tar_data = zstd::decode_all(std::io::Cursor::new(&pkg_data))
        .context("decompressing .pkg.tar.zst with zstd")?;

    // Extract target binary from tar
    extract_from_tar(&tar_data, code_file).context("extracting binary from pacman package")
}

/// Fetch a repo database (.db.tar.gz), using cache.
async fn fetch_repo_db(
    client: &Client,
    cache: &crate::cache::Cache,
    db_url: &str,
    repo: &str,
    arch: &str,
) -> Result<Vec<u8>> {
    let hostname = extract_hostname(db_url);
    let cache_file = format!("{repo}.db.tar.gz");
    let cache_id = format!("{hostname}-{repo}-{arch}");
    let db_key = crate::cache::BinaryCacheKey {
        code_file: cache_file.clone(),
        code_id: cache_id,
        filename: cache_file,
    };

    match cache.get_binary(&db_key) {
        crate::cache::CacheResult::Hit(path) => {
            debug!("using cached repo db: {repo} ({})", path.display());
            return std::fs::read(&path)
                .with_context(|| format!("reading cached repo db: {}", path.display()));
        }
        _ => {
            debug!("cache miss for repo db: {repo}");
        }
    }

    info!("downloading repo database: {db_url}");
    let response = client
        .get(db_url)
        .send()
        .await
        .with_context(|| format!("downloading repo database: {db_url}"))?;

    let status = response.status();
    if !status.is_success() {
        bail!("repo database download failed: {db_url} (HTTP {status})");
    }

    let data = response
        .bytes()
        .await
        .context("reading repo database body")?
        .to_vec();

    info!(
        "downloaded repo database: {repo} ({:.1} KB)",
        data.len() as f64 / 1024.0
    );

    cache.store_binary(&db_key, &data)?;
    Ok(data)
}

/// Parse a .db.tar.gz repo database into package descriptions.
fn parse_db_tar(db_data: &[u8]) -> Result<Vec<PkgDesc>> {
    let gz = flate2::read::GzDecoder::new(db_data);
    let mut archive = tar::Archive::new(gz);
    let mut packages = Vec::new();

    for entry in archive.entries().context("reading db.tar.gz entries")? {
        let mut entry = entry.context("reading db entry")?;
        let path = entry.path().context("reading db entry path")?.into_owned();

        // Only process "desc" files: <pkgname>-<version>/desc
        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if filename != "desc" {
            continue;
        }

        let mut contents = String::new();
        entry
            .read_to_string(&mut contents)
            .context("reading desc file")?;

        if let Some(pkg) = parse_desc(&contents) {
            packages.push(pkg);
        }
    }

    Ok(packages)
}

/// Parse a single `desc` file from the repo database.
///
/// Format: sections separated by blank lines, each section starts with
/// `%FIELDNAME%` followed by value lines.
fn parse_desc(contents: &str) -> Option<PkgDesc> {
    let mut name = None;
    let mut version = None;
    let mut filename = None;
    let mut provides = Vec::new();

    let mut current_field: Option<&str> = None;

    for line in contents.lines() {
        if line.starts_with('%') && line.ends_with('%') && line.len() > 2 {
            current_field = Some(line);
            continue;
        }
        if line.is_empty() {
            current_field = None;
            continue;
        }
        match current_field {
            Some("%NAME%") => name = Some(line.to_string()),
            Some("%VERSION%") => version = Some(line.to_string()),
            Some("%FILENAME%") => filename = Some(line.to_string()),
            Some("%PROVIDES%") => provides.push(line.to_string()),
            _ => {}
        }
    }

    let name = name?;
    let version = version?;
    let filename = filename?;

    Some(PkgDesc {
        name,
        version,
        filename,
        provides,
    })
}

/// Derive a likely package name from a binary filename.
///
/// Strips the `.so.N` suffix and lowercases: `libX11.so.6` → `libx11`,
/// `libdrm.so.2` → `libdrm`. This handles packages that don't declare
/// PROVIDES but follow standard Arch naming conventions.
fn derive_package_name(code_file: &str) -> Option<String> {
    let pos = code_file.find(".so.")?;
    let stem = &code_file[..pos];
    if stem.is_empty() {
        return None;
    }
    Some(stem.to_ascii_lowercase())
}

/// Parse a binary name (e.g., `libglib-2.0.so.0`) into (soname, soversion).
///
/// Returns `("libglib-2.0.so", "0")` — the soname is the part before `.so.`
/// plus `.so`, and the soversion is the first component after `.so.`.
fn parse_binary_soname(binary: &str) -> Option<(&str, &str)> {
    // Find ".so." — the soversion delimiter
    let so_pos = binary.find(".so.")?;
    let soname = &binary[..so_pos + 3]; // includes ".so"
    let soversion_str = &binary[so_pos + 4..]; // after ".so."

    // Take only the first component of the soversion (e.g., "0" from "0.8000.0")
    let soversion = soversion_str.split('.').next().unwrap_or(soversion_str);

    Some((soname, soversion))
}

/// Parse a PROVIDES entry (e.g., `libglib-2.0.so=0-64`) into (soname, soversion).
///
/// Returns `("libglib-2.0.so", "0")`.
fn parse_provides_entry(entry: &str) -> Option<(&str, &str)> {
    // Format: libglib-2.0.so=0-64
    // soname is everything before `=`, soversion is between `=` and `-`
    if !entry.contains(".so") {
        return None;
    }

    let (soname, rest) = entry.split_once('=')?;
    // soversion is the part before the hyphen (if any) in the version
    let soversion = rest.split('-').next().unwrap_or(rest);

    Some((soname, soversion))
}

/// Find a package whose PROVIDES entries match the given binary's soname.
fn find_package_by_provides<'a>(packages: &'a [PkgDesc], code_file: &str) -> Option<&'a PkgDesc> {
    let (bin_soname, bin_soversion) = parse_binary_soname(code_file)?;

    for pkg in packages {
        for prov in &pkg.provides {
            if let Some((prov_soname, prov_soversion)) = parse_provides_entry(prov) {
                if prov_soname == bin_soname && prov_soversion == bin_soversion {
                    return Some(pkg);
                }
            }
        }
    }

    None
}

/// Compute a cache key for a .pkg.tar.zst archive.
///
/// Layout: `<pkg_filename> / <hostname>-<arch> / <pkg_filename>`
fn pkg_cache_key(pkg_url: &str, locator: &PacmanLocator) -> (String, String) {
    let filename = pkg_url
        .rsplit('/')
        .next()
        .unwrap_or("package.pkg.tar.zst")
        .to_string();
    let hostname = extract_hostname(pkg_url);
    let cache_id = format!("{}-{}", hostname, locator.architecture);
    (filename, cache_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pacman_architecture() {
        assert_eq!(pacman_architecture("x86_64"), Some("x86_64"));
        assert_eq!(pacman_architecture("x86"), None);
        assert_eq!(pacman_architecture("arm"), None);
        assert_eq!(pacman_architecture("arm64"), None);
        assert_eq!(pacman_architecture("aarch64"), None);
        assert_eq!(pacman_architecture(""), None);
    }

    #[test]
    fn test_derive_package_name() {
        assert_eq!(
            derive_package_name("libX11.so.6"),
            Some("libx11".to_string())
        );
        assert_eq!(
            derive_package_name("libdrm.so.2"),
            Some("libdrm".to_string())
        );
        assert_eq!(derive_package_name("libc.so.6"), Some("libc".to_string()));
        assert_eq!(
            derive_package_name("libstdc++.so.6"),
            Some("libstdc++".to_string())
        );
        assert_eq!(
            derive_package_name("libglib-2.0.so.0"),
            Some("libglib-2.0".to_string())
        );
        // No .so. → None
        assert_eq!(derive_package_name("libfoo.so"), None);
        assert_eq!(derive_package_name("xul.dll"), None);
        assert_eq!(derive_package_name("firefox"), None);
    }

    #[test]
    fn test_parse_binary_soname() {
        assert_eq!(
            parse_binary_soname("libglib-2.0.so.0"),
            Some(("libglib-2.0.so", "0"))
        );
        assert_eq!(
            parse_binary_soname("libxml2.so.2"),
            Some(("libxml2.so", "2"))
        );
        assert_eq!(parse_binary_soname("libdrm.so.2"), Some(("libdrm.so", "2")));
        assert_eq!(parse_binary_soname("libffi.so.8"), Some(("libffi.so", "8")));
        assert_eq!(
            parse_binary_soname("libglib-2.0.so.0.8000.0"),
            Some(("libglib-2.0.so", "0"))
        );
        // No .so. → None
        assert_eq!(parse_binary_soname("libfoo.so"), None);
        assert_eq!(parse_binary_soname("xul.dll"), None);
    }

    #[test]
    fn test_parse_provides_entry() {
        assert_eq!(
            parse_provides_entry("libglib-2.0.so=0-64"),
            Some(("libglib-2.0.so", "0"))
        );
        assert_eq!(
            parse_provides_entry("libxml2.so=2-64"),
            Some(("libxml2.so", "2"))
        );
        assert_eq!(
            parse_provides_entry("libdrm.so=2-64"),
            Some(("libdrm.so", "2"))
        );
        assert_eq!(
            parse_provides_entry("libffi.so=8-64"),
            Some(("libffi.so", "8"))
        );
        // No = → None
        assert_eq!(parse_provides_entry("bash"), None);
        // No .so → None
        assert_eq!(parse_provides_entry("foo=1.0"), None);
    }

    #[test]
    fn test_parse_desc_fields() {
        let desc = "\
%FILENAME%
glib2-2.82.4-1-x86_64.pkg.tar.zst

%NAME%
glib2

%VERSION%
2.82.4-1

%PROVIDES%
libgio-2.0.so=0-64
libglib-2.0.so=0-64
libgmodule-2.0.so=0-64
libgobject-2.0.so=0-64
libgthread-2.0.so=0-64

%DEPENDS%
glibc
libffi
libsysprof-capture
pcre2
zlib
";
        let pkg = parse_desc(desc).unwrap();
        assert_eq!(pkg.name, "glib2");
        assert_eq!(pkg.version, "2.82.4-1");
        assert_eq!(pkg.filename, "glib2-2.82.4-1-x86_64.pkg.tar.zst");
        assert_eq!(pkg.provides.len(), 5);
        assert_eq!(pkg.provides[0], "libgio-2.0.so=0-64");
        assert_eq!(pkg.provides[1], "libglib-2.0.so=0-64");
    }

    #[test]
    fn test_parse_desc_no_provides() {
        let desc = "\
%FILENAME%
bash-5.2.032-1-x86_64.pkg.tar.zst

%NAME%
bash

%VERSION%
5.2.032-1

%DEPENDS%
readline
glibc
";
        let pkg = parse_desc(desc).unwrap();
        assert_eq!(pkg.name, "bash");
        assert_eq!(pkg.version, "5.2.032-1");
        assert_eq!(pkg.filename, "bash-5.2.032-1-x86_64.pkg.tar.zst");
        assert!(pkg.provides.is_empty());
    }

    #[test]
    fn test_find_package_by_provides() {
        let packages = vec![
            PkgDesc {
                name: "glib2".to_string(),
                version: "2.82.4-1".to_string(),
                filename: "glib2-2.82.4-1-x86_64.pkg.tar.zst".to_string(),
                provides: vec![
                    "libgio-2.0.so=0-64".to_string(),
                    "libglib-2.0.so=0-64".to_string(),
                    "libgobject-2.0.so=0-64".to_string(),
                ],
            },
            PkgDesc {
                name: "libxml2".to_string(),
                version: "2.13.5-1".to_string(),
                filename: "libxml2-2.13.5-1-x86_64.pkg.tar.zst".to_string(),
                provides: vec!["libxml2.so=2-64".to_string()],
            },
        ];

        // Match libglib-2.0.so.0
        let result = find_package_by_provides(&packages, "libglib-2.0.so.0");
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "glib2");

        // Match libgobject-2.0.so.0
        let result = find_package_by_provides(&packages, "libgobject-2.0.so.0");
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "glib2");

        // Match libxml2.so.2
        let result = find_package_by_provides(&packages, "libxml2.so.2");
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "libxml2");

        // No match
        let result = find_package_by_provides(&packages, "libfoo.so.1");
        assert!(result.is_none());

        // No .so. → None (not a shared library)
        let result = find_package_by_provides(&packages, "bash");
        assert!(result.is_none());
    }

    #[test]
    fn test_find_package_by_name() {
        let packages = vec![
            PkgDesc {
                name: "glib2".to_string(),
                version: "2.82.4-1".to_string(),
                filename: "glib2-2.82.4-1-x86_64.pkg.tar.zst".to_string(),
                provides: vec!["libglib-2.0.so=0-64".to_string()],
            },
            PkgDesc {
                name: "libxml2".to_string(),
                version: "2.13.5-1".to_string(),
                filename: "libxml2-2.13.5-1-x86_64.pkg.tar.zst".to_string(),
                provides: vec!["libxml2.so=2-64".to_string()],
            },
        ];

        assert!(packages.iter().any(|p| p.name == "glib2"));
        assert!(packages.iter().any(|p| p.name == "libxml2"));
        assert!(!packages.iter().any(|p| p.name == "nonexistent"));
    }

    #[test]
    fn test_pkg_cache_key() {
        let locator = PacmanLocator {
            package: None,
            mirror: "https://geo.mirror.pkgbuild.com".to_string(),
            repos: vec!["extra".to_string()],
            architecture: "x86_64".to_string(),
        };
        let (file, id) = pkg_cache_key(
            "https://geo.mirror.pkgbuild.com/extra/os/x86_64/glib2-2.82.4-1-x86_64.pkg.tar.zst",
            &locator,
        );
        assert_eq!(file, "glib2-2.82.4-1-x86_64.pkg.tar.zst");
        assert_eq!(id, "geo.mirror.pkgbuild.com-x86_64");
    }

    #[test]
    fn test_parse_db_tar() {
        // Build a synthetic .db.tar.gz with one package
        let mut builder = tar::Builder::new(Vec::new());

        let desc_content = b"\
%FILENAME%
testpkg-1.0-1-x86_64.pkg.tar.zst

%NAME%
testpkg

%VERSION%
1.0-1

%PROVIDES%
libtestpkg.so=0-64
";
        let mut header = tar::Header::new_gnu();
        header.set_size(desc_content.len() as u64);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "testpkg-1.0-1/desc", &desc_content[..])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();

        // Compress with gzip
        use flate2::write::GzEncoder;
        use std::io::Write;
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&tar_data).unwrap();
        let gz_data = encoder.finish().unwrap();

        let packages = parse_db_tar(&gz_data).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "testpkg");
        assert_eq!(packages[0].version, "1.0-1");
        assert_eq!(packages[0].filename, "testpkg-1.0-1-x86_64.pkg.tar.zst");
        assert_eq!(packages[0].provides, vec!["libtestpkg.so=0-64"]);
    }
}
