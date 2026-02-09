// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/// Try to demangle a symbol name as C++ (Itanium ABI) or Rust.
/// Returns the original name unchanged if it's not mangled.
pub fn demangle(name: &str) -> String {
    // Try C++ (Itanium ABI) demangling first
    if let Ok(sym) = cpp_demangle::Symbol::new(name) {
        if let Ok(demangled) = sym.demangle(&cpp_demangle::DemangleOptions::default()) {
            return demangled;
        }
    }

    // Try Rust demangling
    if let Ok(demangled) = rustc_demangle::try_demangle(name) {
        return demangled.to_string();
    }

    name.to_string()
}

/// Demangle a symbol name if `enabled` is true, otherwise return it unchanged.
pub fn maybe_demangle(name: &str, enabled: bool) -> String {
    if enabled {
        demangle(name)
    } else {
        name.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_demangle_cpp_itanium() {
        // _ZN7mozilla3dom7Element12SetAttributeERKNS_6nsAStrES4_R10ErrorResult
        let mangled = "_ZN7mozilla3dom7Element12SetAttributeE";
        let result = demangle(mangled);
        assert!(result.contains("mozilla"));
        assert!(result.contains("dom"));
        assert!(result.contains("Element"));
        assert!(result.contains("SetAttribute"));
        assert!(!result.starts_with("_Z"));
    }

    #[test]
    fn test_demangle_rust() {
        let mangled = "_RNvNtCs1234_5hello5world3foo";
        // Rust v0 mangled symbol — if demangle succeeds, it should not start with _R
        let result = demangle(mangled);
        // Even if the exact output varies, it should attempt demangling
        // For a simpler test, use legacy Rust mangling:
        let legacy = "_ZN4test3foo17h1234567890abcdefE";
        let result2 = demangle(legacy);
        assert!(result2.contains("test"));
        assert!(result2.contains("foo"));
        // Either result should not be the original mangled form
        assert!(result != mangled || result2 != legacy);
    }

    #[test]
    fn test_demangle_already_demangled() {
        let name = "mozilla::dom::Element::SetAttribute";
        assert_eq!(demangle(name), name);
    }

    #[test]
    fn test_demangle_plain_c_symbol() {
        let name = "malloc";
        assert_eq!(demangle(name), "malloc");
    }

    #[test]
    fn test_maybe_demangle_enabled() {
        let mangled = "_ZN7mozilla3dom7Element12SetAttributeE";
        let result = maybe_demangle(mangled, true);
        assert!(!result.starts_with("_Z"));
    }

    #[test]
    fn test_maybe_demangle_disabled() {
        let mangled = "_ZN7mozilla3dom7Element12SetAttributeE";
        let result = maybe_demangle(mangled, false);
        assert_eq!(result, mangled);
    }
}
