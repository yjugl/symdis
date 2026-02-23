// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

pub mod cache_cmd;
pub mod disasm;
pub mod fetch;
pub mod info;
pub mod lookup;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand, ValueEnum};

use crate::config::Config;

const DISASM_LONG_HELP: &str = r#"SYMBOL COVERAGE — NOT LIMITED TO MOZILLA MODULES:

  Mozilla's crash infrastructure automatically downloads Microsoft PDBs for
  ALL modules appearing in crash stacks and uploads .sym files generated from
  them to the Tecken symbol server. This means symdis has symbol coverage for
  many non-Mozilla modules, especially Microsoft-issued Windows system DLLs
  such as ntdll.dll, kernel32.dll, kernelbase.dll, win32u.dll, and many
  others. For these, full annotated disassembly is typically possible —
  Tecken provides the .sym file (generated from the PDB), and the binary
  is fetched from Microsoft's symbol server.

  AI agents: you SHOULD try symdis on any module from a crash report, not
  just Mozilla-issued DLLs. Third-party modules may also sometimes have
  .sym files on Tecken (when their vendors publish PDBs), so it is still
  worth trying.

  Use 'symdis info' to quickly check if symbols are available for a module
  before attempting full disassembly.

CRASH REPORT FIELD MAPPING:

  Socorro JSON field     CLI flag            Notes
  ---------------------  ------------------  -------------------------------
  module.debug_file      --debug-file        Required. E.g. "xul.pdb"
  module.debug_id        --debug-id          Required. 33-char hex string
  frame.module_offset    --offset            Hex (with or without 0x prefix)
  frame.function         --function          Exact match; --fuzzy for substr
  frame.module_offset    --highlight-offset  Marks crash address with ==>
  module.filename        --code-file         Strongly recommended for binary fetch
  module.code_id         --code-id           Strongly recommended for binary fetch
  (from release info)    --version           E.g. "128.0.3". FTP fallback
  (from release info)    --channel           release|beta|esr|nightly|aurora|default
  (from release info)    --build-id          14-digit timestamp (nightly only)
  (snap source paths)    --snap              Snap package name (auto-detected)
  (apt source paths)     --apt               APT binary package name (auto-detected)
  (from release info)    --distro            Ubuntu release codename (e.g., noble)
  (from product name)    --product           firefox|thunderbird|fenix|focus (default: firefox)

BINARY FETCH CHAIN:

  Sources tried in order for the native binary:
    1. Local cache (instant)
    2. Mozilla Tecken symbol server (code-file + code-id)
    3. Microsoft symbol server (Windows .dll/.exe/.sys only)
    4. debuginfod servers (Linux ELF only, requires build ID from
       --code-id or INFO CODE_ID in .sym file)
    5. Snap Store (Linux, when snap detected from sym file or --snap flag)
    6. Ubuntu APT archive (Linux, --apt + --distro required)
    7. Mozilla FTP archive (--version + --channel required):
       - Linux: downloads .tar.xz from /pub/firefox/releases/
       - macOS: downloads .pkg from /pub/firefox/releases/
       - Android: downloads .apk from /pub/fenix/releases/ or /pub/focus/releases/
         (requires --product fenix or --product focus; see sections below)

  ALWAYS provide --code-file and --code-id when available in the crash
  report (module.filename and module.code_id). Without them, binary fetch
  is much less likely to succeed, and you will only get sym-only output
  (function metadata without disassembly). With them, you get full
  annotated disassembly (source lines, call targets, inline frames).

  For Linux modules, if --code-id is not provided, the full ELF build ID
  is automatically extracted from the INFO CODE_ID record in the .sym file
  (when available on Tecken). Debuginfod requires an exact build ID match,
  so either --code-id or INFO CODE_ID is needed for steps 4-6 to work.
  Passing --code-id explicitly always takes precedence.

  Step 5 auto-detects the snap name from source file paths in the .sym
  file (e.g. /build/gnome-42-2204-sdk/parts/...), or use --snap to
  specify it explicitly. Step 6 requires --apt and --distro (see APT
  section below). Providing --version and --channel enables step 7
  as a last resort. The .sym file is always fetched from Tecken using
  --debug-file and --debug-id.

PDB SUPPORT (--pdb):

  For Windows modules (debug-file ends in .pdb), symdis can fetch and
  parse the original PDB file from Microsoft's symbol server or Tecken.
  PDB fetch chain: cache → Tecken (uncompressed or CAB) → Microsoft
  Symbol Server (uncompressed or CAB). Extended timeout (10 min) is used
  because PDB files can be very large (xul.pdb ~1-2 GB as CAB).

  Behavior without --pdb (default):
    1. Fetch .sym file from Tecken (fast, lightweight)
    2. If .sym is unavailable, auto-fallback to PDB fetch+parse

  Behavior with --pdb (explicit preference):
    1. Fetch PDB directly (skip .sym)
    2. If PDB is unavailable, fall back to .sym

  The data source is reported as "binary+pdb" or "pdb" in output.

  .sym vs PDB — WHEN IT MATTERS:

  For kernel drivers and other modules without .sym on Tecken, there is
  no choice: --pdb is the only path to symbols. The comparison below
  only applies to MOZILLA modules where BOTH .sym and PDB exist:

    Feature                 .sym file             PDB (current)
    ----------------------  --------------------  --------------------
    Function names          Demangled C++ names   Demangled with params
                                                  (when public symbol
                                                  available; ~37% of
                                                  funcs in large PDBs)
    Source file paths       VCS paths (hg:...)    VCS paths (from srcsrv
                                                  stream in Mozilla PDBs)
    Source line coverage    Dense (many lines)    Sparse (some modules
                                                  skipped due to pdb
                                                  crate limitations)
    Inline frame tracking   Yes (full)            Yes (from InlineSite
                                                  records + IPI stream)
    Call target names       Demangled             Demangled (MSVC ABI)
    File size               Small (~1 MB)         Large (~100 MB-2 GB)
    Parse speed             Fast                  Slow

  This is because Mozilla's sym generator (dump_syms) performs extensive
  processing of PDB data: demangling, VCS path mapping, inline expansion.
  The .sym file is a pre-processed, optimized representation.

  Auto-fallback handles most cases — you do NOT need --pdb for:
    - WINDOWS KERNEL DRIVERS (.sys files like win32kfull.sys, ntfs.sys,
      tcpip.sys). These never have .sym files on Tecken, so auto-fallback
      kicks in and fetches the PDB automatically. Most kernel functions
      appear as PUBLIC symbols (address only, no size); symdis resolves
      exact function bounds from the PE .pdata section automatically.
    - NON-MOZILLA Windows modules where no .sym exists on Tecken.
      Third-party DLLs, game engines, driver components, and other
      vendor modules — auto-fallback fetches the PDB when .sym is missing.

  When --pdb IS useful (skip the .sym attempt, go straight to PDB):
    - When you KNOW there is no .sym on Tecken and want to skip the
      failed .sym lookup (saves one round-trip).
    - Microsoft system DLLs: Tecken usually HAS .sym files for these
      (ntdll, kernel32, etc.), so .sym is preferred by default. But --pdb
      can be used if you want to cross-check or if a specific version's
      .sym is missing.

  When NOT to use --pdb:
    - Mozilla modules (xul.pdb, mozglue.pdb, etc.) where Tecken has a
      .sym file. The .sym output is richer (denser line coverage,
      consistently demangled function names).

  Remaining limitations:
    - The pdb crate panics on some modules in large PDBs (e.g. xul.pdb);
      these modules are caught and skipped silently, which may result in
      sparser line coverage compared to .sym files.
    - For kernel drivers and other PUBLIC-only modules, there are no
      source line annotations or inline frames (PUBLIC symbols carry
      only an address and name). Call targets within the same module
      ARE resolved from other PUBLIC symbol names.

UBUNTU APT PACKAGES (--apt):

  For Ubuntu system libraries installed via apt (libxml2, mesa, libdrm,
  libffi, etc.), symdis can fetch .deb packages from archive.ubuntu.com
  and extract the target binary. This covers libraries that are NOT in
  snap runtimes and NOT in debuginfod.

  Required flags:
    --apt [PACKAGE]   Enable APT backend. Optional explicit binary package
                      name (e.g., --apt libxml2). When omitted, the source
                      package name is auto-detected from .sym file source
                      paths (e.g., /build/libxml2-2gYHdD/libxml2-2.9.13/...).
    --distro RELEASE  Ubuntu release codename (e.g., noble, jammy, focal).

  How it works:
    1. Downloads the Packages.xz index from archive.ubuntu.com (cached)
    2. Finds the matching .deb package (by Package: or Source: field)
    3. Downloads the .deb, extracts the binary from data.tar.{zst,xz,gz}
    4. Verifies the ELF build ID matches

  When auto-detecting (--apt without a package name), all binary packages
  from the same source are tried until one contains the target binary with
  the correct build ID.

  Architecture note: amd64/i386 packages come from archive.ubuntu.com;
  arm64/armhf packages come from ports.ubuntu.com/ubuntu-ports.

FENIX (FIREFOX FOR ANDROID):

  For Android/Fenix crashes, you MUST pass --product fenix explicitly.
  Auto-detection is not possible because Android .sym files report their
  OS as "Linux", not "Android".

  How to recognize a Fenix crash report:
    - The crash report OS field says "Android"
    - The package name is org.mozilla.firefox or org.mozilla.fenix
    - The build architecture is arm or arm64 (sometimes x86/x86_64)

  Required flags for Fenix binary fetch:
    --product fenix --version <VERSION> --channel <CHANNEL>

  Supported channels: release, beta, nightly (no ESR or aurora).
  For nightly, --build-id is also required.

  The binary is extracted from the APK archive at lib/{abi}/libxul.so,
  where the ABI (arm64-v8a, armeabi-v7a, x86_64, x86) is derived from
  the architecture in the .sym file.

FOCUS (FIREFOX FOCUS FOR ANDROID):

  For Firefox Focus crashes, you MUST pass --product focus explicitly.
  Like Fenix, auto-detection is not possible because Android .sym files
  report their OS as "Linux", not "Android".

  How to recognize a Focus crash report:
    - The crash report Product field says "Focus"
    - The crash report OS field says "Android"
    - The build architecture is arm or arm64 (sometimes x86/x86_64)

  Required flags for Focus binary fetch:
    --product focus --version <VERSION> --channel <CHANNEL>

  Supported channels: release, beta, nightly (no ESR or aurora).
  For nightly, --build-id is also required.

  The binary is extracted from the APK archive at lib/{abi}/libxul.so,
  where the ABI (arm64-v8a, armeabi-v7a, x86_64, x86) is derived from
  the architecture in the .sym file.

GRACEFUL DEGRADATION:

  binary + sym file  ->  Full annotated disassembly (source lines, call
                         targets, inline frames, highlight)
  binary only        ->  Raw disassembly (no source annotations)
  sym file only      ->  Function metadata (name, address, size, source)
                         but no disassembly
  neither            ->  Error

EXAMPLES:

  # Windows module -- disassemble by offset, highlight crash address:
  symdis disasm \
      --debug-file xul.pdb \
      --debug-id EE20BD9ABD8D048B4C4C44205044422E1 \
      --code-file xul.dll --code-id 68d1a3cd87be000 \
      --offset 0x0144c8d2 --highlight-offset 0x0144c8d2

  # Linux module -- with FTP archive fallback:
  symdis disasm \
      --debug-file libxul.so \
      --debug-id 0200CE7B29CF2F761BB067BC519155A00 \
      --code-file libxul.so \
      --code-id 7bce0002cf29762f1bb067bc519155a0cb3f4a31 \
      --version 147.0.3 --channel release \
      --offset 0x31bd35a --highlight-offset 0x31bd35a

  # macOS module -- fat/universal binary from PKG archive:
  symdis disasm \
      --debug-file XUL \
      --debug-id EA25538ED7533E56A4263F6D7050F3D20 \
      --code-file XUL \
      --code-id ea25538ed7533e56a4263f6d7050f3d2 \
      --version 140.6.0esr --channel esr \
      --offset 0x1cb6dd --highlight-offset 0x1cb6dd

  # Ubuntu snap library (auto-detected from sym file source paths):
  symdis disasm \
      --debug-file libglib-2.0.so.0 \
      --debug-id 8EF7C24A1B02B5A64F56BEA31DCF2B1E0 \
      --code-file libglib-2.0.so.0 \
      --code-id 4ac2f78e021ba6b54f56bea31dcf2b1e19c7f3bc \
      --offset 0x625f6

  # Ubuntu APT library (auto-detected source package from sym file):
  symdis disasm \
      --debug-file libgobject-2.0.so.0 \
      --debug-id D5C5BC91262349F50FA62ACC824CB87C0 \
      --code-id 91bcc5d52326f5490fa62acc824cb87c700d0f8a \
      --apt --distro noble \
      --function g_type_check_instance_cast

  # Ubuntu APT library (explicit package name):
  symdis disasm \
      --debug-file libgobject-2.0.so.0 \
      --debug-id D5C5BC91262349F50FA62ACC824CB87C0 \
      --code-id 91bcc5d52326f5490fa62acc824cb87c700d0f8a \
      --apt libglib2.0-0t64 --distro noble \
      --function g_type_check_instance_cast

  # Thunderbird module -- specify --product for non-Firefox products:
  symdis disasm \
      --debug-file libxul.so \
      --debug-id DD03241500B9FE6BA15151BF6FE7A5560 \
      --code-file libxul.so \
      --code-id 152403ddb9006bfea15151bf6fe7a556ee3affd5 \
      --product thunderbird \
      --version 140.7.1esr --channel esr \
      --offset 0x6cad38e

  # Fenix (Firefox for Android) -- MUST use --product fenix:
  symdis disasm \
      --debug-file libxul.so \
      --debug-id 9E915B1A91D7345C4FF0753CF13E53280 \
      --code-file libxul.so \
      --code-id 1a5b919ed7915c344ff0753cf13e532814635a84 \
      --product fenix \
      --version 147.0.3 --channel release \
      --offset 0x03fc39d4 --highlight-offset 0x03fc39d4

  # Focus (Firefox Focus for Android) -- MUST use --product focus:
  symdis disasm \
      --debug-file libxul.so \
      --debug-id 84F39FCE18219B82A8BE7B29D89A0A020 \
      --code-file libxul.so \
      --code-id ce9ff3842118829ba8be7b29d89a0a02224010d2 \
      --product focus \
      --version 147.0.3 --channel release \
      --offset 0x04534a78

  # ARM64 Focus -- PLT calls resolved to import names (memcpy, recvmsg, etc.):
  symdis disasm \
      --debug-file libxul.so \
      --debug-id 84F39FCE18219B82A8BE7B29D89A0A020 \
      --code-file libxul.so \
      --code-id ce9ff3842118829ba8be7b29d89a0a02224010d2 \
      --product focus \
      --version 147.0.3 --channel release \
      --function ProcessIncomingMessages --fuzzy

  # Search by function name (substring match):
  symdis disasm \
      --debug-file xul.pdb \
      --debug-id EE20BD9ABD8D048B4C4C44205044422E1 \
      --code-file xul.dll --code-id 68d1a3cd87be000 \
      --function ProcessIncomingMessages --fuzzy

  # Non-Mozilla module (Windows system DLL) -- works because Mozilla's
  # crash infrastructure generates .sym files from Microsoft PDBs:
  symdis disasm \
      --debug-file ntdll.pdb \
      --debug-id 08A413EE85E91D0377BA33DC3A2641941 \
      --code-file ntdll.dll --code-id 5b6dddee267000 \
      --function NtCreateFile

  # Windows kernel driver (.sys file) -- requires --code-file because
  # the PDB-to-code-file heuristic defaults to .dll. PDB is fetched
  # automatically (no .sym exists for kernel drivers on Tecken).
  # Functions like xxxResolveDesktop are PUBLIC symbols in the PDB;
  # exact function size comes from the PE .pdata section:
  symdis disasm \
      --debug-file win32kfull.pdb \
      --debug-id 874E89B5C0960A8CE25E012F602168591 \
      --code-file win32kfull.sys --code-id 73E41EF8412000 \
      --function xxxResolveDesktop

  # Use PDB for richer symbol data (Windows modules only):
  symdis disasm \
      --debug-file ntdll.pdb \
      --debug-id 08A413EE85E91D0377BA33DC3A2641941 \
      --code-file ntdll.dll --code-id 5b6dddee267000 \
      --function NtCreateFile --pdb

  # JSON output for structured parsing:
  symdis disasm \
      --debug-file xul.pdb \
      --debug-id EE20BD9ABD8D048B4C4C44205044422E1 \
      --code-file xul.dll --code-id 68d1a3cd87be000 \
      --function ProcessIncomingMessages --fuzzy --format json

TIPS:

  - ALWAYS pass --code-file and --code-id from the crash report. Without
    them you usually get sym-only output (no disassembly). With them you
    get full annotated disassembly with source lines and call targets.
  - Use --format json for machine-parseable output.
  - Use --highlight-offset with the crash address (frame.module_offset)
    to mark the faulting instruction with ==> in text output or
    "highlighted": true in JSON output.
  - --offset finds the containing function and disassembles it entirely;
    combine with --highlight-offset to pinpoint the specific instruction.
  - Use 'symdis info' first to check if sym/binary files are available.
  - Use 'symdis lookup --offset 0x...' for quick symbol resolution
    without full disassembly.
  - For nightly builds, --build-id is the 14-digit build timestamp
    (YYYYMMDDHHmmSS) from the crash report's build_id field.
  - For Thunderbird crashes, add --product thunderbird to fetch
    binaries from the Thunderbird FTP archive instead of Firefox.
  - For Fenix (Firefox for Android) crashes, --product fenix is
    REQUIRED. For Focus (Firefox Focus), use --product focus.
    Neither can be auto-detected because Android .sym files report
    OS as "Linux". See the FENIX and FOCUS sections above for details.
  - Don't skip non-Mozilla modules! Crashes in ntdll.dll, kernel32.dll,
    and other Microsoft system DLLs are common and symdis has symbols for
    them. Other third-party modules are also worth trying.
  - Windows kernel drivers (.sys files like win32kfull.sys, tcpip.sys,
    ntfs.sys) are supported. Always provide --code-file for .sys files
    because derive-from-PDB defaults to .dll. PDB is fetched
    automatically (no .sym exists for kernel drivers on Tecken).
  - --pdb skips the .sym lookup and goes straight to PDB. This saves
    one round-trip when you know .sym is unavailable. For Mozilla
    modules, the default .sym path gives better output (denser line
    coverage, consistently demangled function names). For kernel
    drivers and other non-Mozilla modules, auto-fallback already
    fetches PDB when .sym is missing, so --pdb is optional.
  - PUBLIC symbols are searched when --function doesn't match a FUNC
    record. This is common for Windows kernel drivers where PDB data
    only has PUBLIC symbols (address, no size) for many functions.
    When the binary is available, exact function bounds come from
    the PE .pdata section; otherwise size is estimated from the
    distance to the next symbol.
  - Indirect calls through the Import Address Table are automatically
    resolved to their target import names (e.g., "kernel32.dll!CreateFileW").
    On x86-64, these are call [rip+disp]; on x86 32-bit, these are
    call [absolute_va] (the standard IAT calling convention on both
    architectures). If the memory slot does not point to an import,
    symdis also tries reading the on-disk pointer value to resolve
    intra-module function pointer tables.
  - On AArch64, indirect calls via ADRP+LDR+BLR sequences are resolved
    automatically. The engine scans backward from each blr/br instruction
    to find the matching adrp+ldr pair, computes the GOT/IAT slot address,
    and resolves the import name or intra-module target. This covers the
    standard indirect calling convention on AArch64 across all platforms
    (Linux ELF, macOS Mach-O, Windows PE, Android ELF). Register clobber
    detection prevents incorrect resolution when the register chain is
    broken between instructions.
  - On ARM/AArch64 ELF binaries, direct calls to PLT stubs (bl <addr>)
    are resolved to their import names (e.g., "memcpy", "recvmsg").
    This covers the standard calling convention for imported functions
    on Linux ARM and AArch64.
  - On macOS Mach-O binaries, direct calls to __stubs entries (e.g.,
    call <__stubs+0x42> on x86-64, bl <__stubs+0x30> on AArch64) are
    resolved to their import names (e.g., "libSystem.B.dylib!_malloc").
    This covers the standard calling convention for imported functions
    on macOS.
  - For Ubuntu system libraries (libxml2, mesa, libdrm, libffi, etc.),
    use --apt --distro <codename> to fetch binaries from APT packages.
    The source package name is auto-detected from .sym source paths
    (e.g., /build/libxml2-2gYHdD/...). Use --apt <package> to specify
    the binary package name explicitly when auto-detection fails.
  - ARM32 Thumb-2 mode is auto-detected from ELF symbol metadata
    (mapping symbols $t/$a and function symbol Thumb bit). Most
    ARM32 binaries (including Fenix armeabi-v7a) use Thumb-2
    instructions. Without proper detection, disassembly would show
    garbage mnemonics; with detection, you get correct push/mov/bl/ldr."#;

const LOOKUP_LONG_HELP: &str = r#"CRASH REPORT FIELD MAPPING:

  Socorro JSON field     CLI flag        Notes
  ---------------------  --------------  --------------------------------
  module.debug_file      --debug-file    Required. E.g. "xul.pdb"
  module.debug_id        --debug-id      Required. 33-char hex string
  frame.module_offset    --offset        Hex (with or without 0x prefix)
  frame.function         --function      Exact match; --fuzzy for substr

  Operates on the .sym file only (no binary needed). Resolves an offset
  to the containing function name, or a function name to its address and
  size. Useful for quick symbol lookups without full disassembly.

  When looking up by --function, the search order is:
    1. FUNC records (exact name match)
    2. PUBLIC symbols (exact raw name, then demangled name match)
    3. If no match, suggestions from both FUNC and PUBLIC (fuzzy)

  With --fuzzy, both FUNC and PUBLIC symbols are searched by substring
  match (against raw and demangled names).

EXAMPLES:

  # Resolve an offset to a symbol name:
  symdis lookup \
      --debug-file xul.pdb \
      --debug-id EE20BD9ABD8D048B4C4C44205044422E1 \
      --offset 0x0144c8d2

  # Find a function's address by name (substring match):
  symdis lookup \
      --debug-file xul.pdb \
      --debug-id EE20BD9ABD8D048B4C4C44205044422E1 \
      --function ProcessIncomingMessages --fuzzy"#;

const FETCH_LONG_HELP: &str = r#"CRASH REPORT FIELD MAPPING:

  Socorro JSON field     CLI flag        Notes
  ---------------------  --------------  --------------------------------
  module.debug_file      --debug-file    Required. E.g. "xul.pdb"
  module.debug_id        --debug-id      Required. 33-char hex string
  module.filename        --code-file     Strongly recommended for binary fetch
  module.code_id         --code-id       Strongly recommended for binary fetch
  (from release info)    --version       E.g. "128.0.3". FTP fallback
  (from release info)    --channel       release|beta|esr|nightly|aurora|default
  (from release info)    --build-id      14-digit timestamp (nightly only)
  (snap source paths)    --snap          Snap package name (explicit only)
  (apt source paths)     --apt           APT binary package name (explicit only)
  (from release info)    --distro        Ubuntu release codename (e.g., noble)
  (from product name)    --product       firefox|thunderbird|fenix|focus (default: firefox)

  Pre-fetches the .sym file and native binary into the local cache so
  that subsequent disasm calls are instant cache hits. Useful when you
  plan to disassemble multiple functions from the same module. Always
  provide --code-file and --code-id to maximize binary fetch success.

  Binary fetch chain: cache → Tecken → Microsoft (Windows) → debuginfod
  (Linux) → Snap Store (Linux, --snap) → APT (Linux, --apt + --distro)
  → FTP archive (--version + --channel).

  For Linux modules, the full ELF build ID for debuginfod is extracted
  from the INFO CODE_ID record in the .sym file when --code-id is not
  provided.

  With --pdb, also fetches the PDB file from Tecken or Microsoft Symbol
  Server (Windows modules only, debug-file must end in .pdb). The PDB
  is cached separately from the .sym file.

  For Android crashes, --product fenix or --product focus is REQUIRED
  (it cannot be auto-detected because Android .sym files report OS as
  "Linux"). Binary fetch downloads the APK from Mozilla's FTP server
  and extracts the native library from lib/{abi}/ inside the APK.

  Note: snap and APT auto-detection from sym file source paths is only
  available in the disasm command. For fetch, use --snap or --apt
  <package> explicitly.

EXAMPLES:

  # Pre-fetch a Windows module:
  symdis fetch \
      --debug-file xul.pdb \
      --debug-id EE20BD9ABD8D048B4C4C44205044422E1 \
      --code-file xul.dll --code-id 68d1a3cd87be000

  # Pre-fetch a Linux module with FTP archive fallback:
  symdis fetch \
      --debug-file libxul.so \
      --debug-id 0200CE7B29CF2F761BB067BC519155A00 \
      --code-file libxul.so \
      --code-id 7bce0002cf29762f1bb067bc519155a0cb3f4a31 \
      --version 147.0.3 --channel release

  # Pre-fetch a Fenix (Android) module:
  symdis fetch \
      --debug-file libxul.so \
      --debug-id 9E915B1A91D7345C4FF0753CF13E53280 \
      --code-file libxul.so \
      --code-id 1a5b919ed7915c344ff0753cf13e532814635a84 \
      --product fenix \
      --version 147.0.3 --channel release

  # Pre-fetch a Focus (Android) module:
  symdis fetch \
      --debug-file libxul.so \
      --debug-id 84F39FCE18219B82A8BE7B29D89A0A020 \
      --code-file libxul.so \
      --code-id ce9ff3842118829ba8be7b29d89a0a02224010d2 \
      --product focus \
      --version 147.0.3 --channel release

  # Pre-fetch a snap library:
  symdis fetch \
      --debug-file libglib-2.0.so.0 \
      --debug-id 8EF7C24A1B02B5A64F56BEA31DCF2B1E0 \
      --code-file libglib-2.0.so.0 \
      --code-id 4ac2f78e021ba6b54f56bea31dcf2b1e19c7f3bc \
      --snap gnome-42-2204-sdk

  # Pre-fetch an Ubuntu APT library:
  symdis fetch \
      --debug-file libgobject-2.0.so.0 \
      --debug-id D5C5BC91262349F50FA62ACC824CB87C0 \
      --code-id 91bcc5d52326f5490fa62acc824cb87c700d0f8a \
      --apt libglib2.0-0t64 --distro noble

  # Pre-fetch including PDB file:
  symdis fetch \
      --debug-file ntdll.pdb \
      --debug-id 08A413EE85E91D0377BA33DC3A2641941 \
      --code-file ntdll.dll --code-id 5b6dddee267000 \
      --pdb

TIPS:

  - Run 'symdis fetch' once before a series of 'symdis disasm' calls
    on the same module to avoid redundant network requests.
  - Use -v to see cache hit/miss details on stderr."#;

const INFO_LONG_HELP: &str = r#"CRASH REPORT FIELD MAPPING:

  Socorro JSON field     CLI flag        Notes
  ---------------------  --------------  --------------------------------
  module.debug_file      --debug-file    Required. E.g. "xul.pdb"
  module.debug_id        --debug-id      Required. 33-char hex string
  module.filename        --code-file     Optional. For binary availability
  module.code_id         --code-id       Optional. For binary availability
  (from release info)    --version       E.g. "128.0.3". FTP fallback
  (from release info)    --channel       release|beta|esr|nightly|aurora|default
  (from release info)    --build-id      14-digit timestamp (nightly only)
  (from product name)    --product       firefox|thunderbird|fenix|focus (default: firefox)

  Shows module metadata from the .sym file: module name, debug ID, OS,
  architecture, function count, and whether the binary is available.
  Binary availability is checked using the same fetch chain as disasm
  (Tecken → Microsoft → debuginfod → FTP archive).

EXAMPLES:

  # Check module metadata and sym/binary availability:
  symdis info \
      --debug-file xul.pdb \
      --debug-id EE20BD9ABD8D048B4C4C44205044422E1 \
      --code-file xul.dll --code-id 68d1a3cd87be000

  # Check a non-Mozilla module (Windows system DLL):
  symdis info \
      --debug-file ntdll.pdb \
      --debug-id 08A413EE85E91D0377BA33DC3A2641941 \
      --code-file ntdll.dll --code-id 5b6dddee267000

  # Check a Linux module with FTP archive fallback:
  symdis info \
      --debug-file libxul.so \
      --debug-id 0200CE7B29CF2F761BB067BC519155A00 \
      --code-file libxul.so \
      --code-id 7bce0002cf29762f1bb067bc519155a0cb3f4a31 \
      --version 147.0.3 --channel release

  # JSON output:
  symdis info \
      --debug-file xul.pdb \
      --debug-id EE20BD9ABD8D048B4C4C44205044422E1 \
      --code-file xul.dll --code-id 68d1a3cd87be000 \
      --format json

TIPS:

  - Run 'symdis info' before 'symdis disasm' to check whether the sym
    file and binary are available before attempting full disassembly.
  - Provide --code-file and --code-id for accurate binary availability.
  - Use --version and --channel to check FTP archive fallback availability."#;

#[derive(Parser)]
#[command(
    name = "symdis",
    version,
    about = "Symbolic disassembler for Mozilla crash report analysis",
    long_about = "Symbolic disassembler for Mozilla crash report analysis.\n\n\
        Designed for AI agents analyzing Mozilla crash reports. Given a module's \
        debug identifiers and a function name or offset from a crash report, \
        symdis fetches symbols and binaries from Mozilla/Microsoft symbol \
        servers and produces annotated disassembly with source lines, call \
        targets, and inline frames.\n\n\
        Works with ANY module in a crash report, not just Mozilla DLLs. \
        Mozilla's crash infrastructure uploads .sym files to Tecken for all \
        Microsoft modules seen in crash stacks (ntdll, kernel32, etc.).\n\n\
        Subcommands:\n  \
        disasm   Disassemble a function (primary command)\n  \
        lookup   Resolve offset → symbol or symbol → address (sym file only)\n  \
        info     Show module metadata (sym file availability, function count)\n  \
        fetch    Pre-fetch symbols and binary into cache\n  \
        cache    Manage the local cache (path, size, clear, list)\n\n\
        Update check:\n  \
        On each run, symdis checks crates.io in the background for a newer\n  \
        version. If one is found, a notice is printed to stderr after the\n  \
        command completes. The check is cached for 24 hours and can be\n  \
        disabled by setting MOZTOOLS_UPDATE_CHECK=0."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Cache directory path
    #[arg(long, global = true)]
    pub cache_dir: Option<String>,

    /// Output format
    #[arg(long, global = true, default_value = "text")]
    pub format: FormatArg,

    /// Disable C++/Rust symbol demangling
    #[arg(long, global = true)]
    pub no_demangle: bool,

    /// Verbose output (-v info, -vv debug)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Skip network requests; use only cached data
    #[arg(long, global = true)]
    pub offline: bool,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum FormatArg {
    Text,
    Json,
}

#[derive(Subcommand)]
pub enum Command {
    /// Disassemble a function from a module
    Disasm(DisasmArgs),
    /// Resolve a module offset to a symbol name, or a symbol name to an address
    Lookup(LookupArgs),
    /// Show module metadata
    Info(InfoArgs),
    /// Pre-fetch symbols and binary for a module
    Fetch(FetchArgs),
    /// Manage the local cache
    Cache(CacheArgs),
}

#[derive(Parser)]
#[command(after_long_help = DISASM_LONG_HELP)]
pub struct DisasmArgs {
    /// Debug file name (e.g., xul.pdb, libxul.so)
    #[arg(long)]
    pub debug_file: String,

    /// Debug identifier (33-character hex string)
    #[arg(long)]
    pub debug_id: String,

    /// Function name to disassemble
    #[arg(long, conflicts_with = "offset")]
    pub function: Option<String>,

    /// RVA / module offset (hex, with or without 0x prefix)
    #[arg(long, conflicts_with = "function")]
    pub offset: Option<String>,

    /// Disassembly syntax
    #[arg(long, default_value = "intel")]
    pub syntax: SyntaxArg,

    /// Mark a specific offset in the output (auto-extends --max-instructions if needed)
    #[arg(long)]
    pub highlight_offset: Option<String>,

    /// Enable substring/fuzzy matching for --function
    #[arg(long)]
    pub fuzzy: bool,

    /// Safety limit on output size (auto-extended when --highlight-offset falls beyond it)
    #[arg(long, default_value = "2000")]
    pub max_instructions: usize,

    /// Code file name (e.g., xul.dll)
    #[arg(long)]
    pub code_file: Option<String>,

    /// Code identifier
    #[arg(long)]
    pub code_id: Option<String>,

    /// Product version (e.g., "147.0.3") for FTP archive fallback
    #[arg(long)]
    pub version: Option<String>,

    /// Release channel (release, beta, nightly, esr, aurora, default) for FTP archive fallback
    #[arg(long)]
    pub channel: Option<String>,

    /// Build ID timestamp (required for nightly channel only)
    #[arg(long)]
    pub build_id: Option<String>,

    /// Snap package name (auto-detected from sym file source paths if not specified)
    #[arg(long)]
    pub snap: Option<String>,

    /// Enable APT backend for Ubuntu system libraries. Optionally specify
    /// the binary package name; if omitted, the source package name is
    /// auto-detected from sym file source paths.
    #[arg(long, num_args = 0..=1, default_missing_value = "")]
    pub apt: Option<String>,

    /// Ubuntu release codename (e.g., noble, jammy). Required with --apt.
    #[arg(long)]
    pub distro: Option<String>,

    /// Mozilla product: firefox (default), thunderbird, fenix, or focus.
    /// For Android crashes, you MUST specify --product fenix or --product focus.
    /// It cannot be auto-detected (Android .sym files report OS as "Linux").
    #[arg(long, default_value = "firefox")]
    pub product: String,

    /// Prefer PDB over .sym file for symbol data.
    /// Only applicable to Windows modules (debug-file ends in .pdb).
    /// Without this flag, PDB is tried automatically when .sym is unavailable.
    #[arg(long)]
    pub pdb: bool,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum SyntaxArg {
    Intel,
    Att,
}

#[derive(Parser)]
#[command(after_long_help = LOOKUP_LONG_HELP)]
pub struct LookupArgs {
    /// Debug file name
    #[arg(long)]
    pub debug_file: String,

    /// Debug identifier
    #[arg(long)]
    pub debug_id: String,

    /// Function name
    #[arg(long, conflicts_with = "offset")]
    pub function: Option<String>,

    /// RVA / module offset
    #[arg(long, conflicts_with = "function")]
    pub offset: Option<String>,

    /// Enable substring/fuzzy matching for --function
    #[arg(long)]
    pub fuzzy: bool,
}

#[derive(Parser)]
#[command(after_long_help = INFO_LONG_HELP)]
pub struct InfoArgs {
    /// Debug file name
    #[arg(long)]
    pub debug_file: String,

    /// Debug identifier
    #[arg(long)]
    pub debug_id: String,

    /// Code file name
    #[arg(long)]
    pub code_file: Option<String>,

    /// Code identifier
    #[arg(long)]
    pub code_id: Option<String>,

    /// Product version (e.g., "147.0.3") for FTP archive fallback
    #[arg(long)]
    pub version: Option<String>,

    /// Release channel (release, beta, nightly, esr, aurora, default) for FTP archive fallback
    #[arg(long)]
    pub channel: Option<String>,

    /// Build ID timestamp (required for nightly channel only)
    #[arg(long)]
    pub build_id: Option<String>,

    /// Mozilla product: firefox (default), thunderbird, fenix, or focus.
    /// For Android crashes, you MUST specify --product fenix or --product focus.
    /// It cannot be auto-detected (Android .sym files report OS as "Linux").
    #[arg(long, default_value = "firefox")]
    pub product: String,
}

#[derive(Parser)]
#[command(after_long_help = FETCH_LONG_HELP)]
pub struct FetchArgs {
    /// Debug file name
    #[arg(long)]
    pub debug_file: String,

    /// Debug identifier
    #[arg(long)]
    pub debug_id: String,

    /// Code file name
    #[arg(long)]
    pub code_file: Option<String>,

    /// Code identifier
    #[arg(long)]
    pub code_id: Option<String>,

    /// Product version (e.g., "147.0.3") for FTP archive fallback
    #[arg(long)]
    pub version: Option<String>,

    /// Release channel (release, beta, nightly, esr, aurora, default) for FTP archive fallback
    #[arg(long)]
    pub channel: Option<String>,

    /// Build ID timestamp (required for nightly channel only)
    #[arg(long)]
    pub build_id: Option<String>,

    /// Snap package name (not auto-detected; use --snap explicitly for fetch)
    #[arg(long)]
    pub snap: Option<String>,

    /// Enable APT backend for Ubuntu system libraries. Optionally specify
    /// the binary package name; if omitted, requires source package name from
    /// sym file source paths.
    #[arg(long, num_args = 0..=1, default_missing_value = "")]
    pub apt: Option<String>,

    /// Ubuntu release codename (e.g., noble, jammy). Required with --apt.
    #[arg(long)]
    pub distro: Option<String>,

    /// Mozilla product: firefox (default), thunderbird, fenix, or focus.
    /// For Android crashes, you MUST specify --product fenix or --product focus.
    /// It cannot be auto-detected (Android .sym files report OS as "Linux").
    #[arg(long, default_value = "firefox")]
    pub product: String,

    /// Also fetch PDB file from symbol servers.
    /// Only applicable to Windows modules (debug-file ends in .pdb).
    #[arg(long)]
    pub pdb: bool,
}

const CACHE_LONG_HELP: &str = r#"EXAMPLES:

  # Print the cache directory path:
  symdis cache path

  # Show total cache size:
  symdis cache size

  # Delete all cached files:
  symdis cache clear

  # Delete cached files older than 30 days:
  symdis cache clear --older-than 30

  # List cached artifacts for a specific module:
  symdis cache list --debug-file xul.pdb

  # List cached artifacts for a Linux module:
  symdis cache list --debug-file libxul.so"#;

#[derive(Parser)]
#[command(after_long_help = CACHE_LONG_HELP)]
pub struct CacheArgs {
    #[command(subcommand)]
    pub action: CacheAction,
}

#[derive(Subcommand)]
pub enum CacheAction {
    /// Print the cache directory path
    Path,
    /// Print the total size of cached files
    Size,
    /// Delete cached files
    Clear {
        /// Delete files older than N days
        #[arg(long)]
        older_than: Option<u64>,
    },
    /// List cached artifacts for a specific module
    List {
        /// Debug file name to filter by
        #[arg(long)]
        debug_file: String,
    },
}

pub async fn run(cli: Cli) -> Result<()> {
    let config = Config::resolve(&cli)?;

    match cli.command {
        Command::Disasm(ref args) => {
            if args.function.is_none() && args.offset.is_none() {
                bail!("Either --function or --offset must be specified");
            }
            disasm::run(args, &config).await
        }
        Command::Lookup(ref args) => {
            if args.function.is_none() && args.offset.is_none() {
                bail!("Either --function or --offset must be specified");
            }
            lookup::run(args, &config).await
        }
        Command::Info(ref args) => {
            info::run(args, &config).await
        }
        Command::Fetch(ref args) => fetch::run(args, &config).await,
        Command::Cache(args) => cache_cmd::run(args, &config),
    }
}
