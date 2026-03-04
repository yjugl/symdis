// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use pdb::FallibleIterator;

/// Information about a bitfield member.
#[derive(Debug, Clone)]
pub struct BitfieldInfo {
    pub bit_position: u8,
    pub bit_length: u8,
}

/// A single field (data member) in a class/struct/union.
#[derive(Debug, Clone)]
pub struct FieldLayout {
    pub offset: u64,
    pub size: u64,
    pub type_name: String,
    pub field_name: String,
    pub bitfield: Option<BitfieldInfo>,
}

/// A base class of a class/struct.
#[derive(Debug, Clone)]
pub struct BaseClassLayout {
    pub offset: u64,
    pub size: u64,
    pub name: String,
    pub is_virtual: bool,
}

/// Complete layout of a class/struct/union from PDB type information.
#[derive(Debug, Clone)]
pub struct TypeLayout {
    pub name: String,
    pub kind: String,
    pub size: u64,
    pub base_classes: Vec<BaseClassLayout>,
    pub fields: Vec<FieldLayout>,
}

/// Map PrimitiveKind to its C name.
fn primitive_name(kind: pdb::PrimitiveKind) -> &'static str {
    use pdb::PrimitiveKind::*;
    match kind {
        NoType => "<no type>",
        Void => "void",
        Char => "char",
        UChar => "unsigned char",
        RChar => "char",
        WChar => "wchar_t",
        RChar16 => "char16_t",
        RChar32 => "char32_t",
        I8 => "int8_t",
        U8 => "uint8_t",
        Short => "short",
        UShort => "unsigned short",
        I16 => "int16_t",
        U16 => "uint16_t",
        Long => "long",
        ULong => "unsigned long",
        I32 => "int32_t",
        U32 => "uint32_t",
        Quad => "int64_t",
        UQuad => "uint64_t",
        I64 => "int64_t",
        U64 => "uint64_t",
        Octa => "__int128",
        UOcta => "unsigned __int128",
        I128 => "__int128",
        U128 => "unsigned __int128",
        F16 => "_Float16",
        F32 => "float",
        F32PP => "float",
        F48 => "_Float48",
        F64 => "double",
        F80 => "long double",
        F128 => "__float128",
        Complex32 => "_Complex float",
        Complex64 => "_Complex double",
        Complex80 => "_Complex long double",
        Complex128 => "_Complex __float128",
        Bool8 => "bool",
        Bool16 => "bool16",
        Bool32 => "BOOL",
        Bool64 => "bool64",
        HRESULT => "HRESULT",
        _ => "<unknown>",
    }
}

/// Map PrimitiveKind to its byte size.
fn primitive_size(kind: pdb::PrimitiveKind) -> u64 {
    use pdb::PrimitiveKind::*;
    match kind {
        NoType | Void => 0,
        Char | UChar | RChar | I8 | U8 | Bool8 => 1,
        WChar | Short | UShort | I16 | U16 | Bool16 | F16 => 2,
        Long | ULong | I32 | U32 | F32 | F32PP | Bool32 | HRESULT => 4,
        Quad | UQuad | I64 | U64 | F64 | Bool64 | Complex32 => 8,
        F80 | Complex64 => {
            // F80 is 10 bytes but typically padded to 12 or 16
            // Complex64 is 16 bytes (two doubles)
            // Use the most common sizes
            match kind {
                F80 => 10,
                Complex64 => 16,
                _ => 0,
            }
        }
        Octa | UOcta | I128 | U128 | F128 | Complex80 => 16,
        Complex128 => 32,
        F48 => 6,
        _ => 0,
    }
}

/// Forward-reference resolution map: type name → non-forward-reference TypeIndex.
/// PDB types like `RefPtr<T>` often appear as forward references (size 0) at the
/// index used by field members. This map lets us follow them to the real definition.
type FwdMap = HashMap<String, pdb::TypeIndex>;

/// Resolve a TypeIndex to a human-readable type name string.
fn resolve_type_name(type_finder: &pdb::TypeFinder<'_>, index: pdb::TypeIndex) -> String {
    let item = match type_finder.find(index) {
        Ok(item) => item,
        Err(_) => return format!("<type 0x{:x}>", index.0),
    };

    match item.parse() {
        Ok(pdb::TypeData::Primitive(prim)) => {
            let base = primitive_name(prim.kind);
            match prim.indirection {
                Some(_) => format!("{base} *"),
                None => base.to_string(),
            }
        }
        Ok(pdb::TypeData::Class(class)) => {
            let kind = match class.kind {
                pdb::ClassKind::Class => "class",
                pdb::ClassKind::Struct => "struct",
                pdb::ClassKind::Interface => "interface",
            };
            format!("{kind} {}", class.name)
        }
        Ok(pdb::TypeData::Union(union)) => {
            format!("union {}", union.name)
        }
        Ok(pdb::TypeData::Enumeration(e)) => {
            format!("enum {}", e.name)
        }
        Ok(pdb::TypeData::Pointer(ptr)) => {
            let inner = resolve_type_name(type_finder, ptr.underlying_type);
            format!("{inner} *")
        }
        Ok(pdb::TypeData::Modifier(m)) => {
            let inner = resolve_type_name(type_finder, m.underlying_type);
            let mut result = String::new();
            if m.constant {
                result.push_str("const ");
            }
            if m.volatile {
                result.push_str("volatile ");
            }
            result.push_str(&inner);
            result
        }
        Ok(pdb::TypeData::Array(arr)) => {
            let elem = resolve_type_name(type_finder, arr.element_type);
            if let Some(dim) = arr.dimensions.first() {
                let elem_size =
                    resolve_type_size(type_finder, &HashMap::new(), arr.element_type).unwrap_or(1);
                if elem_size > 0 {
                    format!("{elem}[{}]", dim / elem_size as u32)
                } else {
                    format!("{elem}[{dim}]")
                }
            } else {
                format!("{elem}[]")
            }
        }
        Ok(pdb::TypeData::Bitfield(bf)) => resolve_type_name(type_finder, bf.underlying_type),
        Ok(pdb::TypeData::Procedure(_)) => "<function>".to_string(),
        Ok(pdb::TypeData::MemberFunction(_)) => "<member function>".to_string(),
        _ => format!("<type 0x{:x}>", index.0),
    }
}

/// Resolve a TypeIndex to its byte size.
///
/// When the index points to a forward reference (size 0), `fwd_map` is consulted
/// to find the non-forward-reference definition which has the real size.
fn resolve_type_size(
    type_finder: &pdb::TypeFinder<'_>,
    fwd_map: &FwdMap,
    index: pdb::TypeIndex,
) -> Option<u64> {
    let item = type_finder.find(index).ok()?;

    match item.parse().ok()? {
        pdb::TypeData::Primitive(prim) => match prim.indirection {
            Some(ind) => Some(indirection_size(ind)),
            None => Some(primitive_size(prim.kind)),
        },
        pdb::TypeData::Class(class) => {
            if class.size == 0 && class.properties.forward_reference() {
                // Follow forward reference to real definition
                let name = class.name.to_string().into_owned();
                if let Some(&real_idx) = fwd_map.get(&name)
                    && real_idx != index
                {
                    return resolve_type_size(type_finder, fwd_map, real_idx);
                }
            }
            Some(class.size)
        }
        pdb::TypeData::Union(union) => {
            if union.size == 0 && union.properties.forward_reference() {
                let name = union.name.to_string().into_owned();
                if let Some(&real_idx) = fwd_map.get(&name)
                    && real_idx != index
                {
                    return resolve_type_size(type_finder, fwd_map, real_idx);
                }
            }
            Some(union.size)
        }
        pdb::TypeData::Enumeration(e) => resolve_type_size(type_finder, fwd_map, e.underlying_type),
        pdb::TypeData::Pointer(ptr) => {
            // Pointer size from attributes
            let size = match ptr.attributes.pointer_kind() {
                pdb::PointerKind::Near16 => 2,
                pdb::PointerKind::Near32 => 4,
                pdb::PointerKind::Ptr64 => 8,
                _ => 8, // default to 64-bit
            };
            Some(size)
        }
        pdb::TypeData::Modifier(m) => resolve_type_size(type_finder, fwd_map, m.underlying_type),
        pdb::TypeData::Array(arr) => {
            // Array dimensions encode byte sizes
            arr.dimensions.first().map(|d| u64::from(*d))
        }
        pdb::TypeData::Bitfield(bf) => resolve_type_size(type_finder, fwd_map, bf.underlying_type),
        _ => None,
    }
}

/// Get pointer size from Indirection.
fn indirection_size(ind: pdb::Indirection) -> u64 {
    match ind {
        pdb::Indirection::Near16 => 2,
        pdb::Indirection::Far16 | pdb::Indirection::Huge16 => 4,
        pdb::Indirection::Near32 => 4,
        pdb::Indirection::Far32 => 6,
        pdb::Indirection::Near64 => 8,
        pdb::Indirection::Near128 => 16,
    }
}

/// Extract fields and base classes from a FieldList, following continuation chains.
fn extract_fields(
    type_finder: &pdb::TypeFinder<'_>,
    fwd_map: &FwdMap,
    fields_index: pdb::TypeIndex,
) -> Result<(Vec<BaseClassLayout>, Vec<FieldLayout>)> {
    let mut base_classes = Vec::new();
    let mut fields = Vec::new();
    let mut current = Some(fields_index);

    while let Some(idx) = current {
        let item = type_finder
            .find(idx)
            .context("resolving FieldList type index")?;
        let field_list = match item.parse() {
            Ok(pdb::TypeData::FieldList(fl)) => fl,
            _ => break,
        };

        for field_data in &field_list.fields {
            match field_data {
                pdb::TypeData::Member(member) => {
                    // Check if the field_type is a bitfield
                    let (type_name, size, bitfield) =
                        resolve_member_type(type_finder, fwd_map, member.field_type);

                    fields.push(FieldLayout {
                        offset: member.offset,
                        size,
                        type_name,
                        field_name: member.name.to_string().into_owned(),
                        bitfield,
                    });
                }
                pdb::TypeData::BaseClass(base) => {
                    let name = resolve_type_name(type_finder, base.base_class);
                    let size =
                        resolve_type_size(type_finder, fwd_map, base.base_class).unwrap_or(0);
                    base_classes.push(BaseClassLayout {
                        offset: u64::from(base.offset),
                        size,
                        name,
                        is_virtual: false,
                    });
                }
                pdb::TypeData::VirtualBaseClass(vbase) => {
                    let name = resolve_type_name(type_finder, vbase.base_class);
                    let size =
                        resolve_type_size(type_finder, fwd_map, vbase.base_class).unwrap_or(0);
                    base_classes.push(BaseClassLayout {
                        offset: u64::from(vbase.base_pointer_offset),
                        size,
                        name,
                        is_virtual: true,
                    });
                }
                pdb::TypeData::VirtualFunctionTablePointer(vfptr) => {
                    let size = resolve_type_size(type_finder, fwd_map, vfptr.table).unwrap_or(8);
                    fields.push(FieldLayout {
                        offset: 0, // vfptr is always at offset 0 within its class
                        size,
                        type_name: "<vfptr>".to_string(),
                        field_name: "<vfptr>".to_string(),
                        bitfield: None,
                    });
                }
                // Skip non-instance-data members
                pdb::TypeData::Nested(_)
                | pdb::TypeData::StaticMember(_)
                | pdb::TypeData::Method(_)
                | pdb::TypeData::OverloadedMethod(_)
                | pdb::TypeData::Enumerate(_) => {}
                _ => {}
            }
        }

        current = field_list.continuation;
    }

    Ok((base_classes, fields))
}

/// Resolve a member's field_type, handling bitfields specially.
fn resolve_member_type(
    type_finder: &pdb::TypeFinder<'_>,
    fwd_map: &FwdMap,
    index: pdb::TypeIndex,
) -> (String, u64, Option<BitfieldInfo>) {
    if let Ok(item) = type_finder.find(index)
        && let Ok(pdb::TypeData::Bitfield(bf)) = item.parse()
    {
        let type_name = resolve_type_name(type_finder, bf.underlying_type);
        let size = resolve_type_size(type_finder, fwd_map, bf.underlying_type).unwrap_or(0);
        return (
            type_name,
            size,
            Some(BitfieldInfo {
                bit_position: bf.position,
                bit_length: bf.length,
            }),
        );
    }

    let type_name = resolve_type_name(type_finder, index);
    let size = resolve_type_size(type_finder, fwd_map, index).unwrap_or(0);
    (type_name, size, None)
}

/// Summary of TPI (type program information) availability in a PDB.
#[derive(Debug, Clone)]
pub struct TpiSummary {
    /// Total number of named class/struct/union types with definitions (non-forward-references).
    pub type_count: usize,
}

/// Quickly probe whether a PDB file has type information (TPI stream).
///
/// Returns `Some(TpiSummary)` if the PDB can be opened and has types,
/// or `None` if the PDB cannot be opened or the TPI stream is empty/unreadable.
/// This is much faster than `extract_type_layout` because it only counts
/// non-forward-reference types without building a full name map.
pub fn probe_type_info(path: &Path) -> Option<TpiSummary> {
    let file = std::fs::File::open(path).ok()?;
    let mut pdb = pdb::PDB::open(file).ok()?;
    let type_info = pdb.type_information().ok()?;
    let mut iter = type_info.iter();

    let mut type_count = 0usize;

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        while let Ok(Some(item)) = iter.next() {
            match item.parse() {
                Ok(pdb::TypeData::Class(class)) => {
                    if !class.properties.forward_reference() {
                        type_count += 1;
                    }
                }
                Ok(pdb::TypeData::Union(union)) => {
                    if !union.properties.forward_reference() {
                        type_count += 1;
                    }
                }
                _ => {}
            }
        }
    }));

    if result.is_err() {
        // Panicked during iteration — return what we counted so far
        if type_count > 0 {
            return Some(TpiSummary { type_count });
        }
        return None;
    }

    if type_count == 0 {
        return None;
    }

    Some(TpiSummary { type_count })
}

/// Extract the layout of a C++ type from PDB type information.
///
/// Opens the PDB file at `path`, iterates the TPI stream to find a type
/// matching `type_name`, and returns its field layout.
///
/// If `fuzzy` is true, performs substring matching; if multiple types match,
/// returns an error listing the matches (capped at 20).
pub fn extract_type_layout(path: &Path, type_name: &str, fuzzy: bool) -> Result<TypeLayout> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("opening PDB file: {}", path.display()))?;
    let mut pdb = pdb::PDB::open(file).context("parsing PDB file")?;

    let type_info = pdb.type_information().context("reading TPI stream")?;
    let mut type_finder = type_info.finder();

    // Single pass: build TypeFinder and collect name→TypeIndex map.
    // We skip forward references (they have no fields/size).
    let mut name_map: HashMap<String, pdb::TypeIndex> = HashMap::new();
    let mut iter = type_info.iter();

    // Wrap in catch_unwind for robustness (same pattern as symbols/pdb.rs)
    let build_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        while let Ok(Some(item)) = iter.next() {
            type_finder.update(&iter);
            match item.parse() {
                Ok(pdb::TypeData::Class(class)) => {
                    if !class.properties.forward_reference() {
                        name_map.insert(class.name.to_string().into_owned(), item.index());
                    }
                }
                Ok(pdb::TypeData::Union(union)) => {
                    if !union.properties.forward_reference() {
                        name_map.insert(union.name.to_string().into_owned(), item.index());
                    }
                }
                _ => {}
            }
        }
    }));

    if build_result.is_err() {
        bail!("PDB type iteration panicked (corrupted TPI stream?)");
    }

    if name_map.is_empty() {
        bail!(
            "PDB has no type information (TPI stream is empty). \
             This PDB may be a stripped/public symbol PDB without private type data."
        );
    }

    // Search for the type
    let target_index = if fuzzy {
        // Substring match
        let matches: Vec<(&String, &pdb::TypeIndex)> = name_map
            .iter()
            .filter(|(name, _)| name.contains(type_name))
            .collect();

        match matches.len() {
            0 => bail!(
                "no type matching '{type_name}' found in PDB ({} types scanned)",
                name_map.len()
            ),
            1 => *matches[0].1,
            n => {
                let cap = 20.min(n);
                let mut list = String::new();
                for (name, _) in matches.iter().take(cap) {
                    list.push_str(&format!("  {name}\n"));
                }
                if n > cap {
                    list.push_str(&format!("  ... and {} more\n", n - cap));
                }
                bail!(
                    "fuzzy search for '{type_name}' matched {n} types. \
                     Use a more specific name or --type with exact name:\n{list}"
                );
            }
        }
    } else {
        // Exact match
        match name_map.get(type_name) {
            Some(&idx) => idx,
            None => {
                // Check for partial matches to give a helpful error
                let suggestions: Vec<&String> = name_map
                    .keys()
                    .filter(|name| name.contains(type_name))
                    .take(10)
                    .collect();

                if suggestions.is_empty() {
                    bail!(
                        "type '{type_name}' not found in PDB ({} types scanned)",
                        name_map.len()
                    );
                } else {
                    let mut list = String::new();
                    for name in &suggestions {
                        list.push_str(&format!("  {name}\n"));
                    }
                    bail!(
                        "type '{type_name}' not found in PDB. Similar types:\n{list}\
                         Use --fuzzy for substring matching."
                    );
                }
            }
        }
    };

    // Parse the target type
    let item = type_finder
        .find(target_index)
        .context("resolving target type")?;

    match item.parse().context("parsing target type")? {
        pdb::TypeData::Class(class) => {
            let kind = match class.kind {
                pdb::ClassKind::Class => "class",
                pdb::ClassKind::Struct => "struct",
                pdb::ClassKind::Interface => "interface",
            };

            let (mut base_classes, mut fields) = if let Some(fields_idx) = class.fields {
                extract_fields(&type_finder, &name_map, fields_idx)?
            } else {
                (Vec::new(), Vec::new())
            };

            base_classes.sort_by_key(|b| b.offset);
            fields.sort_by_key(|f| f.offset);

            Ok(TypeLayout {
                name: class.name.to_string().into_owned(),
                kind: kind.to_string(),
                size: class.size,
                base_classes,
                fields,
            })
        }
        pdb::TypeData::Union(union) => {
            let (_, mut fields) = if union.fields.0 > 0 {
                extract_fields(&type_finder, &name_map, union.fields)?
            } else {
                (Vec::new(), Vec::new())
            };

            fields.sort_by_key(|f| f.offset);

            Ok(TypeLayout {
                name: union.name.to_string().into_owned(),
                kind: "union".to_string(),
                size: union.size,
                base_classes: Vec::new(),
                fields,
            })
        }
        other => {
            bail!(
                "type '{}' is {:?}, expected class/struct/union",
                type_name,
                std::mem::discriminant(&other)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_primitive_name_common_types() {
        assert_eq!(primitive_name(pdb::PrimitiveKind::Void), "void");
        assert_eq!(primitive_name(pdb::PrimitiveKind::Char), "char");
        assert_eq!(primitive_name(pdb::PrimitiveKind::UChar), "unsigned char");
        assert_eq!(primitive_name(pdb::PrimitiveKind::Long), "long");
        assert_eq!(primitive_name(pdb::PrimitiveKind::ULong), "unsigned long");
        assert_eq!(primitive_name(pdb::PrimitiveKind::I32), "int32_t");
        assert_eq!(primitive_name(pdb::PrimitiveKind::U32), "uint32_t");
        assert_eq!(primitive_name(pdb::PrimitiveKind::I64), "int64_t");
        assert_eq!(primitive_name(pdb::PrimitiveKind::U64), "uint64_t");
        assert_eq!(primitive_name(pdb::PrimitiveKind::F32), "float");
        assert_eq!(primitive_name(pdb::PrimitiveKind::F64), "double");
        assert_eq!(primitive_name(pdb::PrimitiveKind::Bool8), "bool");
        assert_eq!(primitive_name(pdb::PrimitiveKind::HRESULT), "HRESULT");
        assert_eq!(primitive_name(pdb::PrimitiveKind::WChar), "wchar_t");
        assert_eq!(primitive_name(pdb::PrimitiveKind::RChar16), "char16_t");
        assert_eq!(primitive_name(pdb::PrimitiveKind::RChar32), "char32_t");
    }

    #[test]
    fn test_primitive_size_common_types() {
        assert_eq!(primitive_size(pdb::PrimitiveKind::Void), 0);
        assert_eq!(primitive_size(pdb::PrimitiveKind::Char), 1);
        assert_eq!(primitive_size(pdb::PrimitiveKind::UChar), 1);
        assert_eq!(primitive_size(pdb::PrimitiveKind::Bool8), 1);
        assert_eq!(primitive_size(pdb::PrimitiveKind::Short), 2);
        assert_eq!(primitive_size(pdb::PrimitiveKind::UShort), 2);
        assert_eq!(primitive_size(pdb::PrimitiveKind::WChar), 2);
        assert_eq!(primitive_size(pdb::PrimitiveKind::Long), 4);
        assert_eq!(primitive_size(pdb::PrimitiveKind::ULong), 4);
        assert_eq!(primitive_size(pdb::PrimitiveKind::I32), 4);
        assert_eq!(primitive_size(pdb::PrimitiveKind::U32), 4);
        assert_eq!(primitive_size(pdb::PrimitiveKind::F32), 4);
        assert_eq!(primitive_size(pdb::PrimitiveKind::HRESULT), 4);
        assert_eq!(primitive_size(pdb::PrimitiveKind::Quad), 8);
        assert_eq!(primitive_size(pdb::PrimitiveKind::UQuad), 8);
        assert_eq!(primitive_size(pdb::PrimitiveKind::I64), 8);
        assert_eq!(primitive_size(pdb::PrimitiveKind::U64), 8);
        assert_eq!(primitive_size(pdb::PrimitiveKind::F64), 8);
        assert_eq!(primitive_size(pdb::PrimitiveKind::I128), 16);
        assert_eq!(primitive_size(pdb::PrimitiveKind::U128), 16);
    }

    #[test]
    fn test_indirection_size() {
        assert_eq!(indirection_size(pdb::Indirection::Near16), 2);
        assert_eq!(indirection_size(pdb::Indirection::Near32), 4);
        assert_eq!(indirection_size(pdb::Indirection::Near64), 8);
        assert_eq!(indirection_size(pdb::Indirection::Near128), 16);
    }
}
