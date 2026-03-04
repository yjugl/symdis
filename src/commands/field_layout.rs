// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::fmt::Write;

use anyhow::{Result, bail};
use serde::Serialize;

use super::FieldLayoutArgs;
use crate::cache::Cache;
use crate::config::{Config, OutputFormat};
use crate::fetch;
use crate::symbols::tpi::{self, TypeLayout};

pub async fn run(args: &FieldLayoutArgs, config: &Config) -> Result<()> {
    // Validate: debug_file must be a .pdb
    if !args.debug_file.to_ascii_lowercase().ends_with(".pdb") {
        bail!(
            "field-layout requires a PDB debug file (got '{}').\n\
             .sym files do not contain type information.",
            args.debug_file
        );
    }

    let cache = Cache::new(&config.cache_dir, config.miss_ttl_hours);
    let client = fetch::build_http_client(config)?;

    // Fetch PDB
    let pdb_path =
        fetch::fetch_pdb_file(&client, &cache, config, &args.debug_file, &args.debug_id).await?;

    // Extract type layout
    let layout = tpi::extract_type_layout(&pdb_path, &args.type_name, args.fuzzy)?;

    // Parse --offset if provided
    let query_offset = match &args.offset {
        Some(s) => {
            let s = s
                .strip_prefix("0x")
                .or_else(|| s.strip_prefix("0X"))
                .unwrap_or(s);
            Some(u64::from_str_radix(s, 16).map_err(|_| {
                anyhow::anyhow!(
                    "invalid hex offset: '{}'. Use hex (with or without 0x prefix).",
                    args.offset.as_deref().unwrap_or("")
                )
            })?)
        }
        None => None,
    };

    match config.format {
        OutputFormat::Text => {
            let text = format_text(&args.debug_file, &args.debug_id, &layout, query_offset);
            print!("{text}");
        }
        OutputFormat::Json => {
            let json = format_json(&args.debug_file, &args.debug_id, &layout, query_offset);
            println!("{json}");
        }
    }

    Ok(())
}

/// Find which field covers a given byte offset.
fn find_field_at_offset(layout: &TypeLayout, offset: u64) -> Option<&tpi::FieldLayout> {
    layout.fields.iter().find(|f| {
        if f.size > 0 {
            offset >= f.offset && offset < f.offset + f.size
        } else {
            offset == f.offset
        }
    })
}

/// Find which base class covers a given byte offset (when no field matches).
fn find_base_at_offset(layout: &TypeLayout, offset: u64) -> Option<&tpi::BaseClassLayout> {
    layout.base_classes.iter().find(|b| {
        if b.size > 0 {
            offset >= b.offset && offset < b.offset + b.size
        } else {
            offset == b.offset
        }
    })
}

/// Format type layout as text output.
fn format_text(
    debug_file: &str,
    debug_id: &str,
    layout: &TypeLayout,
    query_offset: Option<u64>,
) -> String {
    let mut out = String::new();

    // Header
    writeln!(out, "; Module: {debug_file} ({debug_id})").unwrap();
    writeln!(
        out,
        "; Type: {} {} (size: 0x{:X}, {} bytes)",
        layout.kind, layout.name, layout.size, layout.size
    )
    .unwrap();
    writeln!(out, ";").unwrap();

    // Base classes
    if !layout.base_classes.is_empty() {
        writeln!(out, "; Base classes:").unwrap();
        for base in &layout.base_classes {
            let virtual_marker = if base.is_virtual { " (virtual)" } else { "" };
            let highlight = match query_offset {
                Some(q) if base.size > 0 && q >= base.offset && q < base.offset + base.size => {
                    // Only highlight base if no field matches
                    if find_field_at_offset(layout, q).is_none() {
                        "==> "
                    } else {
                        ";   "
                    }
                }
                _ => ";   ",
            };
            writeln!(
                out,
                "{highlight}0x{:03X}  (0x{:03X})  {}{virtual_marker}",
                base.offset, base.size, base.name,
            )
            .unwrap();
        }
        writeln!(out, ";").unwrap();
    }

    // Fields
    if !layout.fields.is_empty() {
        writeln!(out, "; Fields:").unwrap();

        // Compute column widths for alignment
        let max_type_len = layout
            .fields
            .iter()
            .map(|f| f.type_name.len())
            .max()
            .unwrap_or(0)
            .max(4);

        for field in &layout.fields {
            let is_highlighted = query_offset.is_some_and(|q| {
                if field.size > 0 {
                    q >= field.offset && q < field.offset + field.size
                } else {
                    q == field.offset
                }
            });

            let prefix = if is_highlighted { "==> " } else { ";   " };

            let bitfield_suffix = match &field.bitfield {
                Some(bf) => format!("  [bit {}:{}]", bf.bit_position, bf.bit_length),
                None => String::new(),
            };

            writeln!(
                out,
                "{prefix}0x{:03X}  (0x{:03X})  {:<width$}  {}{bitfield_suffix}",
                field.offset,
                field.size,
                field.type_name,
                field.field_name,
                width = max_type_len,
            )
            .unwrap();
        }
    }

    // If offset was queried but no match found
    if let Some(q) = query_offset
        && find_field_at_offset(layout, q).is_none()
        && find_base_at_offset(layout, q).is_none()
    {
        if q >= layout.size {
            writeln!(
                out,
                ";\n; WARNING: offset 0x{q:X} is beyond the type size (0x{:X})",
                layout.size
            )
            .unwrap();
        } else {
            writeln!(
                out,
                ";\n; WARNING: offset 0x{q:X} falls in padding (no field at this offset)"
            )
            .unwrap();
        }
    }

    out
}

// --- JSON output ---

#[derive(Serialize)]
struct JsonFieldLayoutOutput {
    module: JsonModule,
    #[serde(rename = "type")]
    type_info: JsonTypeInfo,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    base_classes: Vec<JsonBaseClass>,
    fields: Vec<JsonField>,
    #[serde(skip_serializing_if = "Option::is_none")]
    query_offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    query_match: Option<JsonQueryMatch>,
}

#[derive(Serialize)]
struct JsonModule {
    debug_file: String,
    debug_id: String,
}

#[derive(Serialize)]
struct JsonTypeInfo {
    name: String,
    kind: String,
    size: u64,
}

#[derive(Serialize)]
struct JsonBaseClass {
    offset: u64,
    size: u64,
    name: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    is_virtual: bool,
}

#[derive(Serialize)]
struct JsonField {
    offset: u64,
    size: u64,
    #[serde(rename = "type")]
    type_name: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    bitfield: Option<JsonBitfield>,
}

#[derive(Serialize)]
struct JsonBitfield {
    bit_position: u8,
    bit_length: u8,
}

#[derive(Serialize)]
struct JsonQueryMatch {
    offset: u64,
    size: u64,
    #[serde(rename = "type")]
    type_name: String,
    name: String,
    kind: String, // "field" or "base_class"
}

/// Format type layout as JSON output.
fn format_json(
    debug_file: &str,
    debug_id: &str,
    layout: &TypeLayout,
    query_offset: Option<u64>,
) -> String {
    let query_match = query_offset.and_then(|q| {
        if let Some(field) = find_field_at_offset(layout, q) {
            Some(JsonQueryMatch {
                offset: field.offset,
                size: field.size,
                type_name: field.type_name.clone(),
                name: field.field_name.clone(),
                kind: "field".to_string(),
            })
        } else {
            find_base_at_offset(layout, q).map(|base| JsonQueryMatch {
                offset: base.offset,
                size: base.size,
                type_name: base.name.clone(),
                name: base.name.clone(),
                kind: "base_class".to_string(),
            })
        }
    });

    let output = JsonFieldLayoutOutput {
        module: JsonModule {
            debug_file: debug_file.to_string(),
            debug_id: debug_id.to_string(),
        },
        type_info: JsonTypeInfo {
            name: layout.name.clone(),
            kind: layout.kind.clone(),
            size: layout.size,
        },
        base_classes: layout
            .base_classes
            .iter()
            .map(|b| JsonBaseClass {
                offset: b.offset,
                size: b.size,
                name: b.name.clone(),
                is_virtual: b.is_virtual,
            })
            .collect(),
        fields: layout
            .fields
            .iter()
            .map(|f| JsonField {
                offset: f.offset,
                size: f.size,
                type_name: f.type_name.clone(),
                name: f.field_name.clone(),
                bitfield: f.bitfield.as_ref().map(|bf| JsonBitfield {
                    bit_position: bf.bit_position,
                    bit_length: bf.bit_length,
                }),
            })
            .collect(),
        query_offset,
        query_match,
    };

    serde_json::to_string_pretty(&output).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbols::tpi::{BaseClassLayout, BitfieldInfo, FieldLayout};

    fn sample_layout() -> TypeLayout {
        TypeLayout {
            name: "TestClass".to_string(),
            kind: "class".to_string(),
            size: 0x40,
            base_classes: vec![BaseClassLayout {
                offset: 0,
                size: 0x10,
                name: "class BaseClass".to_string(),
                is_virtual: false,
            }],
            fields: vec![
                FieldLayout {
                    offset: 0x10,
                    size: 8,
                    type_name: "int64_t".to_string(),
                    field_name: "mValue".to_string(),
                    bitfield: None,
                },
                FieldLayout {
                    offset: 0x18,
                    size: 4,
                    type_name: "unsigned long".to_string(),
                    field_name: "mFlags".to_string(),
                    bitfield: None,
                },
                FieldLayout {
                    offset: 0x1C,
                    size: 4,
                    type_name: "unsigned long".to_string(),
                    field_name: "mBitA".to_string(),
                    bitfield: Some(BitfieldInfo {
                        bit_position: 0,
                        bit_length: 1,
                    }),
                },
                FieldLayout {
                    offset: 0x20,
                    size: 8,
                    type_name: "class Foo *".to_string(),
                    field_name: "mPtr".to_string(),
                    bitfield: None,
                },
            ],
        }
    }

    #[test]
    fn test_format_text_no_offset() {
        let layout = sample_layout();
        let text = format_text("test.pdb", "ABC123", &layout, None);
        assert!(text.contains("Module: test.pdb (ABC123)"));
        assert!(text.contains("class TestClass (size: 0x40, 64 bytes)"));
        assert!(text.contains("BaseClass"));
        assert!(text.contains("mValue"));
        assert!(text.contains("mFlags"));
        assert!(text.contains("mPtr"));
        assert!(!text.contains("==>"));
    }

    #[test]
    fn test_format_text_with_offset_match() {
        let layout = sample_layout();
        let text = format_text("test.pdb", "ABC123", &layout, Some(0x10));
        assert!(text.contains("==> 0x010"));
        assert!(text.contains("mValue"));
        // Only the matched field should be highlighted
        let highlight_count = text.matches("==>").count();
        assert_eq!(highlight_count, 1);
    }

    #[test]
    fn test_format_text_with_offset_in_base() {
        let layout = sample_layout();
        // Offset 0x08 is in the base class region, no field covers it
        let text = format_text("test.pdb", "ABC123", &layout, Some(0x08));
        assert!(text.contains("==> 0x000"));
        assert!(text.contains("BaseClass"));
    }

    #[test]
    fn test_format_text_with_offset_beyond_size() {
        let layout = sample_layout();
        let text = format_text("test.pdb", "ABC123", &layout, Some(0x100));
        assert!(text.contains("WARNING: offset 0x100 is beyond the type size"));
    }

    #[test]
    fn test_format_text_bitfield() {
        let layout = sample_layout();
        let text = format_text("test.pdb", "ABC123", &layout, None);
        assert!(text.contains("[bit 0:1]"));
    }

    #[test]
    fn test_format_json_no_offset() {
        let layout = sample_layout();
        let json = format_json("test.pdb", "ABC123", &layout, None);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"]["name"], "TestClass");
        assert_eq!(v["type"]["kind"], "class");
        assert_eq!(v["type"]["size"], 0x40);
        assert!(v["query_offset"].is_null());
        assert!(v["query_match"].is_null());
        assert_eq!(v["fields"].as_array().unwrap().len(), 4);
        assert_eq!(v["base_classes"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_format_json_with_offset_match() {
        let layout = sample_layout();
        let json = format_json("test.pdb", "ABC123", &layout, Some(0x20));
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["query_offset"], 0x20);
        assert_eq!(v["query_match"]["name"], "mPtr");
        assert_eq!(v["query_match"]["kind"], "field");
        assert_eq!(v["query_match"]["offset"], 0x20);
        assert_eq!(v["query_match"]["size"], 8);
    }

    #[test]
    fn test_format_json_with_offset_base_class() {
        let layout = sample_layout();
        let json = format_json("test.pdb", "ABC123", &layout, Some(0x08));
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["query_match"]["kind"], "base_class");
        assert_eq!(v["query_match"]["name"], "class BaseClass");
    }

    #[test]
    fn test_format_json_with_offset_no_match() {
        let layout = sample_layout();
        // 0x30 is in padding (no field covers it)
        let json = format_json("test.pdb", "ABC123", &layout, Some(0x30));
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["query_offset"], 0x30);
        assert!(v["query_match"].is_null());
    }

    #[test]
    fn test_find_field_at_offset_exact() {
        let layout = sample_layout();
        let field = find_field_at_offset(&layout, 0x10).unwrap();
        assert_eq!(field.field_name, "mValue");
    }

    #[test]
    fn test_find_field_at_offset_within() {
        let layout = sample_layout();
        // 0x14 is within mValue (offset 0x10, size 8)
        let field = find_field_at_offset(&layout, 0x14).unwrap();
        assert_eq!(field.field_name, "mValue");
    }

    #[test]
    fn test_find_field_at_offset_none() {
        let layout = sample_layout();
        // 0x30 is in padding
        assert!(find_field_at_offset(&layout, 0x30).is_none());
    }

    #[test]
    fn test_find_base_at_offset() {
        let layout = sample_layout();
        let base = find_base_at_offset(&layout, 0x08).unwrap();
        assert_eq!(base.name, "class BaseClass");
    }
}
