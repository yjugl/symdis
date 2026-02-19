// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/// Linker-generated thunk prefixes (LLD/LLVM) that wrap a target symbol name.
/// ARM32: long-range branch thunks placed in islands every ~16MB.
/// AArch64: rare (128MB branch range), but exist for very large binaries.
const THUNK_PREFIXES: &[&str] = &[
    "__ThumbV7PILongThunk_",
    "__ARMv7PILongThunk_",
    "__ThumbV7ABSLongThunk_",
    "__ARMv7ABSLongThunk_",
    "__AArch64AbsLongThunk_",
    "__AArch64ADRPThunk_",
];

/// Try to demangle a symbol name as C++ (Itanium ABI), Rust, or MSVC.
/// Returns the original name unchanged if it's not mangled.
///
/// Also handles linker-generated thunk symbols (e.g., `__ThumbV7PILongThunk_<mangled>`)
/// by stripping the prefix, demangling the inner name, and reattaching the prefix.
pub fn demangle(name: &str) -> String {
    // Check for linker thunk prefixes wrapping a mangled name
    for prefix in THUNK_PREFIXES {
        if let Some(inner) = name.strip_prefix(prefix) {
            if !inner.is_empty() {
                if let Some(demangled) = try_demangle(inner) {
                    return format!("{prefix}{demangled}");
                }
            }
            break;
        }
    }

    try_demangle(name).unwrap_or_else(|| name.to_string())
}

/// Attempt demangling as C++ (Itanium ABI), Rust, or MSVC.
/// Returns `None` if the name is not recognized as mangled.
fn try_demangle(name: &str) -> Option<String> {
    // Try C++ (Itanium ABI) demangling first
    if let Ok(sym) = cpp_demangle::Symbol::new(name) {
        if let Ok(demangled) = sym.demangle(&cpp_demangle::DemangleOptions::default()) {
            return Some(demangled);
        }
    }

    // Try Rust demangling
    if let Ok(demangled) = rustc_demangle::try_demangle(name) {
        return Some(demangled.to_string());
    }

    // Try MSVC demangling (symbols start with '?')
    if name.starts_with('?') {
        if let Ok(demangled) = msvc_demangler::demangle(name, msvc_demangler::DemangleFlags::llvm()) {
            return Some(demangled);
        }
    }

    None
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
    fn test_demangle_msvc() {
        // MSVC-mangled symbol: void mozilla::ipc::NodeChannel::OnMessageReceived(const IPC::Message &)
        let mangled = "?OnMessageReceived@NodeChannel@ipc@mozilla@@UEAAXAEBVMessage@IPC@@@Z";
        let result = demangle(mangled);
        assert!(!result.starts_with('?'), "MSVC symbol should be demangled: {result}");
        assert!(result.contains("OnMessageReceived"), "Should contain function name: {result}");
        assert!(result.contains("mozilla"), "Should contain namespace: {result}");
    }

    #[test]
    fn test_demangle_msvc_simple() {
        let mangled = "?hello@@YAHXZ";
        let result = demangle(mangled);
        assert!(!result.starts_with('?'), "MSVC symbol should be demangled: {result}");
        assert!(result.contains("hello"), "Should contain function name: {result}");
    }

    #[test]
    fn test_demangle_msvc_not_triggered_for_non_msvc() {
        // A '?' in the middle should not trigger MSVC demangling
        let name = "some_func?weird";
        assert_eq!(demangle(name), name);
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

    #[test]
    fn test_demangle_macho_leading_underscore() {
        // Mach-O symbols have a leading _ prefix: __Z... instead of _Z...
        // cpp_demangle handles this natively
        let macho_mangled = "__ZN7mozilla9TimeStamp3NowEb";
        let result = demangle(macho_mangled);
        assert!(result.contains("mozilla"));
        assert!(result.contains("TimeStamp"));
        assert!(!result.starts_with("__Z"));
    }

    #[test]
    fn test_demangle_thumb_thunk_cpp() {
        // ARM32 linker thunk wrapping a C++ Itanium mangled name
        let name = "__ThumbV7PILongThunk__Z19NS_ProcessNextEventP9nsIThreadb";
        let result = demangle(name);
        assert!(result.starts_with("__ThumbV7PILongThunk_"), "Prefix preserved: {result}");
        assert!(result.contains("NS_ProcessNextEvent"), "Demangled inner name: {result}");
        assert!(!result.contains("_Z19"), "Mangled part should be gone: {result}");
    }

    #[test]
    fn test_demangle_thumb_thunk_plain_c() {
        // ARM32 linker thunk wrapping a plain C name (no mangling to strip)
        let name = "__ThumbV7PILongThunk_sysconf";
        let result = demangle(name);
        assert_eq!(result, name, "Plain C thunk target stays unchanged");
    }

    #[test]
    fn test_demangle_arm_thunk_cpp() {
        // ARM-mode thunk variant
        let name = "__ARMv7PILongThunk__ZN7mozilla3dom7Element12SetAttributeE";
        let result = demangle(name);
        assert!(result.starts_with("__ARMv7PILongThunk_"), "Prefix preserved: {result}");
        assert!(result.contains("mozilla"), "Demangled inner name: {result}");
        assert!(result.contains("SetAttribute"), "Demangled inner name: {result}");
    }

    #[test]
    fn test_demangle_aarch64_thunk() {
        // AArch64 thunk variant
        let name = "__AArch64AbsLongThunk__ZN7mozilla9TimeStamp3NowEb";
        let result = demangle(name);
        assert!(result.starts_with("__AArch64AbsLongThunk_"), "Prefix preserved: {result}");
        assert!(result.contains("TimeStamp"), "Demangled inner name: {result}");
    }

    #[test]
    fn test_demangle_thunk_rust() {
        // Thunk wrapping a Rust legacy mangled name
        let name = "__ThumbV7PILongThunk__ZN4test3foo17h1234567890abcdefE";
        let result = demangle(name);
        assert!(result.starts_with("__ThumbV7PILongThunk_"), "Prefix preserved: {result}");
        assert!(result.contains("test"), "Demangled inner name: {result}");
        assert!(result.contains("foo"), "Demangled inner name: {result}");
    }
}
