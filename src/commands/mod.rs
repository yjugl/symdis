// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

pub mod cache_cmd;
pub mod disasm;
pub mod fetch;
pub mod field_layout;
pub mod info;
pub mod lookup;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand, ValueEnum};

use crate::config::Config;

const DISASM_BEFORE_HELP: &str = "\
QUICKSTART: socorro-cli crash CRASH_ID --full | symdis disasm --socorro-json -
For all flags, examples, and full documentation, run: symdis disasm --help";

const DISASM_BEFORE_LONG_HELP: &str = r#"QUICKSTART — USE --socorro-json (RECOMMENDED):

  The easiest way to disassemble a crash is to pass the full socorro JSON.
  All module IDs, offsets, product, version, channel, distro, and backend
  flags (--apt, --pacman, --snap) are extracted automatically:

    socorro-cli crash CRASH_ID --full | symdis disasm --socorro-json -

  Or from a saved file:

    symdis disasm --socorro-json /tmp/crash.json

  --socorro-json has two modes:

  1. FRAME MODE (default): disassemble the function at a specific frame.
     The module, offset, and highlight are all taken from the frame.

       # Crash frame (frame 0, default):
       symdis disasm --socorro-json crash.json

       # A different frame (e.g. the caller):
       symdis disasm --socorro-json crash.json --frame 1

  2. MODULE MODE: disassemble a specific function in a specific module.
     Use --debug-file to name the module (its IDs are resolved from
     json_dump.modules) and --function or --offset to pick the function.
     This is frame-independent.

       symdis disasm --socorro-json crash.json --debug-file libxul.so \
           --function SnowWhiteKiller --fuzzy

       symdis disasm --socorro-json crash.json --debug-file ntdll.pdb \
           --function RtlFreeHeap

  In both modes, product, version, channel, distro, and backend flags
  are auto-extracted from the crash report.

  Auto-extracted fields:
    - --debug-file, --debug-id, --code-file, --code-id from the module
    - --offset, --highlight-offset from the frame's module_offset (frame mode)
    - --version, --channel, --build-id from the crash report
    - --product from the crash report (Fenix -> fenix, Focus -> focus,
      Thunderbird -> thunderbird)
    - --distro from json_dump.lsb_release.codename
    - --apt auto-enabled when distro matches a known APT codename
    - --pacman auto-enabled when lsb_release.id is Arch-like
    - --snap guessed from Ubuntu codename (gnome-42-2204-sdk, core22,
      gnome-46-2404-sdk, core24) when source-path detection doesn't
      find a snap name"#;

const DISASM_AFTER_LONG_HELP: &str = r#"MANUAL FLAGS (FALLBACK):

  --socorro-json can fail when the JSON is malformed, truncated, or missing
  required fields (e.g. no modules array, no crashing_thread). It also
  requires socorro-cli or another tool to fetch the full JSON.

  When --socorro-json is not available (e.g. working from a partial crash
  report, a stack trace, or individual module IDs), specify flags manually.
  This requires extracting the right values yourself.

SYMBOL COVERAGE — NOT LIMITED TO MOZILLA MODULES:

  symdis supports Windows (PE), Linux (ELF), macOS (Mach-O), and Android
  modules. It is NOT limited to Mozilla-issued modules — you should try it
  on ANY module from a crash report:

  Windows: Mozilla's crash infrastructure downloads Microsoft PDBs for ALL
  modules appearing in crash stacks and uploads .sym files to Tecken. This
  means full annotated disassembly is typically possible for Microsoft
  system DLLs (ntdll.dll, kernel32.dll, kernelbase.dll, win32u.dll, etc.).
  Windows kernel drivers (.sys) and GPU drivers are also supported via PDB
  auto-fallback from Microsoft/Intel/AMD/NVIDIA symbol servers.

  Linux: system libraries (libglib, libxml2, mesa, libdrm, etc.) can be
  fetched via debuginfod, Snap Store, APT packages (Debian/Ubuntu), or
  pacman packages (Arch Linux). Mozilla modules are fetched from Tecken
  and the FTP archive.

  macOS: binaries are extracted from .pkg archives on Mozilla's FTP server.
  Fat (universal) binaries are handled with automatic architecture selection.

  Android: Fenix (Firefox for Android) and Focus (Firefox Focus) APKs are
  fetched from Mozilla's FTP archive (--product fenix / --product focus).

  AI agents: you SHOULD try symdis on any module from a crash report.
  Third-party modules may also have .sym files on Tecken (when their
  vendors publish PDBs), and Linux system libraries are reachable via
  debuginfod/Snap/APT/pacman.

  Use 'symdis info' to quickly check if symbols are available for a module
  before attempting full disassembly.

CRASH REPORT FIELD MAPPING (for manual flag use):

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
  lsb_release.codename   --distro            E.g. "noble", "bookworm", "kali-rolling"
  (arch linux)           --pacman            Pacman package name (auto-detected via PROVIDES)
  (from product name)    --product           firefox|thunderbird|fenix|focus (default: firefox)

BINARY FETCH CHAIN:

  Sources tried in order for the native binary:
    1. Local cache (instant)
    2. Mozilla Tecken symbol server (code-file + code-id)
    3. Microsoft symbol server (Windows .dll/.exe/.sys only)
    4. debuginfod servers (Linux ELF only, requires build ID from
       --code-id or INFO CODE_ID in .sym file)
    5. Snap Store (Linux, when snap detected from sym file or --snap flag)
    6. APT archive (Linux, --apt + --distro required; supports Ubuntu + Debian)
    7. Pacman packages (Linux x86_64, --pacman; Arch Linux + derivatives)
    8. Mozilla FTP archive (--version + --channel required):
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
  so either --code-id or INFO CODE_ID is needed for steps 4-7 to work.
  Passing --code-id explicitly always takes precedence.

  Step 5 auto-detects the snap name from source file paths in the .sym
  file (e.g. /build/gnome-42-2204-sdk/parts/...), or use --snap to
  specify it explicitly. Step 6 requires --apt and --distro (see APT
  section below). Step 7 requires --pacman (see PACMAN section below).
  Providing --version and --channel enables step 8 as a last resort.
  The .sym file is always fetched from Tecken using --debug-file and
  --debug-id.

PDB SUPPORT (AUTOMATIC FOR WINDOWS MODULES):

  For Windows modules (debug-file ends in .pdb), symdis can fetch and
  parse the original PDB file from symbol servers or Tecken. PDB is
  the primary symbol format for all non-Mozilla Windows modules —
  including Microsoft system DLLs, kernel drivers, GPU drivers, and
  third-party vendor modules — and is fetched AUTOMATICALLY when .sym
  is unavailable (no --pdb flag required).

  PDB fetch chain: cache → Tecken (uncompressed or CAB) → Microsoft →
  Intel → AMD → NVIDIA (all use symsrv protocol, uncompressed or CAB).
  Extended timeout (10 min) is used because PDB files can be very large
  (xul.pdb ~1-2 GB as CAB). GPU driver PDBs (nvoglv64.pdb, amdxc64.pdb,
  etc.) are fetched from vendor servers automatically.

  Behavior without --pdb (default):
    1. Fetch .sym file from Tecken (fast, lightweight)
    2. If .sym is unavailable, auto-fallback to PDB fetch+parse
    This is the most common path for kernel drivers, third-party DLLs,
    and other non-Mozilla modules — PDB is fetched automatically.

  Behavior with --pdb (explicit preference):
    1. Fetch PDB directly (skip .sym)
    2. If PDB is unavailable, fall back to .sym
    Useful when you know .sym is unavailable and want to skip the
    failed lookup (saves one round-trip), or when you need type info
    for field-layout.

  The data source is reported as "binary+pdb" or "pdb" in output.

  .sym vs PDB — WHEN TO USE WHICH:

  For most non-Mozilla Windows modules (kernel drivers, third-party
  DLLs, GPU drivers, Microsoft system DLLs without .sym on Tecken),
  there is NO choice — PDB is the only symbol source and is fetched
  automatically. The guidance below only applies when BOTH formats
  are available (primarily Mozilla modules).

  PDB files contain MORE information than .sym files — specifically,
  C++ type information (class/struct layouts, field offsets, sizes) that
  enables the 'symdis field-layout' command. However, PDB files are
  much larger and slower to fetch and parse.

  RULE OF THUMB FOR AI AGENTS:
    - For DISASSEMBLY (disasm, lookup): prefer .sym (default). It is
      lightweight, fast, and has denser source line coverage. You do
      NOT need --pdb for disassembly — auto-fallback fetches PDB
      when .sym is unavailable.
    - For TYPE INFORMATION (field-layout): PDB is REQUIRED. The .sym
      format has no type data at all. Use 'symdis field-layout' to
      look up struct field offsets, or 'symdis info --pdb' to check
      if type info is available before running field-layout.
    - JUST RUN THE COMMAND. Auto-fallback handles the common case:
      symdis automatically tries PDB when .sym is unavailable. You
      do not need to pre-check whether .sym exists.

  The comparison below only applies to MOZILLA modules where both
  .sym and PDB exist (for all other Windows modules, PDB is the
  only and primary symbol source — no comparison needed):

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
    Type information        None                  Full (TPI stream —
                                                  class/struct layouts,
                                                  field offsets, sizes;
                                                  enables field-layout)
    File size               Small (~1 MB)         Large (~100 MB-2 GB)
    Parse speed             Fast                  Slow

  For Mozilla modules, .sym is preferred for disassembly because
  Mozilla's sym generator (dump_syms) pre-processes PDB data:
  demangling, VCS path mapping, inline expansion. The .sym file is
  a lightweight, optimized format. PDB's unique advantage is type
  information, which .sym lacks entirely.

  Auto-fallback handles most cases — you do NOT need --pdb for:
    - WINDOWS KERNEL DRIVERS (.sys files like win32kfull.sys, ntfs.sys,
      tcpip.sys). These never have .sym files on Tecken, so auto-fallback
      kicks in and fetches the PDB automatically. Most kernel functions
      appear as PUBLIC symbols (address only, no size); symdis resolves
      exact function bounds from the PE .pdata section automatically.
      Kernel driver disassembly is a first-class use case.
    - NON-MOZILLA Windows modules where no .sym exists on Tecken.
      Third-party DLLs, game engines, driver components, GPU drivers,
      and other vendor modules — auto-fallback fetches the PDB when
      .sym is missing. This works across Microsoft, Intel, AMD, and
      NVIDIA symbol servers.

  When --pdb IS useful (skip the .sym attempt, go straight to PDB):
    - When you KNOW there is no .sym on Tecken and want to skip the
      failed .sym lookup (saves one round-trip).
    - When you plan to run field-layout afterward — use 'symdis fetch
      --pdb' to pre-cache the PDB, then run field-layout.

  When NOT to use --pdb for disassembly:
    - Mozilla modules (xul.pdb, mozglue.pdb, etc.) where Tecken has a
      .sym file. The .sym output has denser line coverage and
      consistently demangled function names.

  Notes on PDB-only modules (kernel drivers, vendor DLLs, etc.):
    - PUBLIC symbols carry only an address and name (no source lines,
      no inline frames). Disassembly shows raw instructions with call
      target resolution but without source annotations.
    - Call targets within the same module ARE resolved from other
      PUBLIC symbol names.
    - When the binary is available (fetched from Microsoft/vendor
      servers), exact function bounds come from the PE .pdata section.
    - The pdb crate panics on some modules in large PDBs (e.g.
      xul.pdb); these are caught and skipped silently, which may
      result in sparser line coverage compared to .sym files.

APT PACKAGES (--apt, DEBIAN/UBUNTU):

  For system libraries installed via apt (libxml2, mesa, libdrm, libffi,
  etc.), symdis can fetch .deb packages from APT repositories and extract
  the target binary. Supports Ubuntu, Debian, and derivatives (Kali,
  Parrot, MX, etc. via --mirror). This covers libraries that are NOT in
  snap runtimes and NOT in debuginfod.

  Required flags:
    --apt [PACKAGE]   Enable APT backend. Optional explicit binary package
                      name (e.g., --apt libxml2). When omitted, the source
                      package name is auto-detected from .sym file source
                      paths (e.g., /build/libxml2-2gYHdD/libxml2-2.9.13/...).
    --distro RELEASE  Release codename (e.g., noble, bookworm, sid).

  Optional flags:
    --mirror URL      Custom APT mirror URL (for Raspberry Pi OS, Kali,
                      or any Debian-based distribution with custom repos).
    --components LIST Comma-separated component list (default: "main").
                      Only used with --mirror.

  DETERMINING --distro FROM THE CRASH REPORT:

    Use the lsb_release.codename field from the crash report JSON —
    pass it directly as --distro. Examples from real crash reports:

      lsb_release.id   lsb_release.codename   --mirror needed?
      ----------------  ---------------------  ----------------
      Ubuntu            noble                  no
      debian (Debian)   bookworm, trixie       no
      Pop               noble                  no (Ubuntu-based)
      antiX             bookworm               no (Debian-based)
      debian (RPi OS)   bookworm               no (Debian-based)
      kali              kali-rolling           yes (see below)
      debian (Parrot)   echo                   yes (see below)

    For Kali:  --mirror https://http.kali.org/kali --components main
    For Parrot: --mirror https://deb.parrot.sh/parrot
                --components main,contrib,non-free

    Derivatives like antiX, MX Linux, Raspberry Pi OS, and Pop!_OS
    report their Debian/Ubuntu base codename in lsb_release.codename,
    so --distro works directly with no --mirror needed (their system
    libraries come from the upstream Debian/Ubuntu archive).

  DETERMINING --apt PACKAGE NAME:

    In most cases, omit the package name and let auto-detection work:
      symdis disasm ... --apt --distro noble

    Auto-detection reads the .sym file's source paths looking for
    patterns like /build/<source>-<hash>/<source>-<version>/... or
    /usr/src/<source>-<version>/... and searches by source package name.

    When auto-detection fails (sym paths lack /build/ or /usr/src/
    prefixes), provide the binary package name explicitly:
      symdis disasm ... --apt libglib2.0-0 --distro bookworm

    To find the binary package name from the .so filename:
      1. The package usually matches the library name with dots and
         hyphens rearranged. Common pattern:
           libfoo-X.Y.so.Z → libfooX.Y-Z   (e.g., libglib-2.0.so.0 → libglib2.0-0)
           libfoo.so.N     → libfooN        (e.g., libxml2.so.2 → libxml2)
           libfoo.so.N     → libfooN-0      (e.g., libdrm.so.2 → libdrm2)
      2. Ubuntu noble (24.04) renamed many packages with a "t64" suffix
         for the 64-bit time_t transition:
           libglib2.0-0 (bookworm) → libglib2.0-0t64 (noble)
      3. If the first guess fails, symdis prints the available package
         names it found in the index — check the error output.
      4. Try --apt without a package name first. If the sym file has
         source paths, auto-detection avoids this guessing entirely.

  How it works:
    1. Downloads the Packages index from the archive mirror (tries .xz,
       falls back to .gz; cached)
    2. Finds the matching .deb package (by Package: or Source: field)
    3. Downloads the .deb, extracts the binary from data.tar.{zst,xz,gz}
    4. Verifies the ELF build ID matches

  When auto-detecting (--apt without a package name), all binary packages
  from the same source are tried until one contains the target binary with
  the correct build ID.

  Architecture note (Ubuntu only): amd64/i386 packages come from
  archive.ubuntu.com; arm64/armhf from ports.ubuntu.com/ubuntu-ports.

PACMAN PACKAGES (--pacman, ARCH LINUX):

  For system libraries on Arch Linux and derivatives (CachyOS, Manjaro,
  EndeavourOS, etc.), symdis can fetch .pkg.tar.zst packages from pacman
  repositories and extract the target binary. Currently x86_64 only
  (Arch Linux ARM is a separate project).

  Required flags:
    --pacman [PACKAGE]  Enable pacman backend. Optional explicit package
                        name (e.g., --pacman glib2). When omitted, the
                        package is auto-detected (see below).

  Optional flags:
    --mirror URL        Override the default Arch mirror
                        (https://geo.mirror.pkgbuild.com). Use this for
                        derivatives like Manjaro or CachyOS that use
                        different repositories.

  HOW TO RECOGNIZE AN ARCH LINUX CRASH REPORT:

    - lsb_release.id: "Arch" (or "CachyOS", "ManjaroLinux", "EndeavourOS")
    - lsb_release.codename: "rolling" (Arch has no release codenames)
    - No lsb_release.codename or lsb_release.id: check os_pretty_version
      for "Arch Linux" or derivative names

    Key indicator: Arch crashes will NOT match any --distro codename
    (no "noble", "bookworm", etc.) because Arch is rolling release.

  PACKAGE AUTO-DETECTION:

    In most cases, just use --pacman without a package name:
      symdis disasm ... --pacman --function g_main_context_iteration

    Auto-detection uses three matching strategies in order:
      1. PROVIDES matching: matches the binary's soname (e.g.,
         libglib-2.0.so.0) against PROVIDES entries in the repo database
         (e.g., libglib-2.0.so=0-64). Works for most libraries including
         glib2, cairo, pango, gtk3, dbus, wayland, fontconfig, freetype2,
         libffi, libpulse, libstdc++, and many others.
      2. Name-based fallback: derives a package name from the binary
         filename (e.g., libX11.so.6 → libx11, libdrm.so.2 → libdrm).
         Works when the package name matches the library name.
      3. If both fail, an error with a suggested --pacman <name> hint.

    Known edge case requiring explicit naming:
      libc.so.6  → --pacman glibc  (package name doesn't match library)

    Most other libraries auto-detect correctly with --pacman alone.

  How it works:
    1. Downloads the repo database (.db.tar.gz, ~3-8 MB; cached) from
       core, extra, and multilib repositories
    2. Matches package by PROVIDES soname or derived package name
    3. Downloads the .pkg.tar.zst package, decompresses with zstd
    4. Extracts the binary from the tar archive
    5. Verifies the ELF build ID matches

  IMPORTANT: Arch is rolling release, so the binary in the repo is always
  the LATEST version. If the crash is from an older package version, the
  build ID will not match and binary fetch will fail (you still get
  sym-only output). This is inherent to Arch — old packages are not kept.

  NOTE: Arch debuginfod only indexes -debug packages — it does NOT serve
  executables. This means the pacman backend is the only way to fetch
  binaries for Arch Linux crashes.

  For derivatives with custom mirrors:
    --pacman --mirror https://mirror.cachyos.org/repo/x86_64/cachyos
    --pacman --mirror https://repo.manjaro.org/stable/extra/x86_64

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

EXAMPLES (manual flags — prefer --socorro-json when possible):

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

  # Debian APT library (bookworm):
  symdis disasm \
      --debug-file libglib-2.0.so.0 \
      --debug-id 958EC2424AF21D728E8E159F42DBC5410 \
      --code-id 42c28e95f24a721d8e8e159f42dbc541f0ff353d \
      --apt libglib2.0-0 --distro bookworm \
      --function g_main_context_iteration

  # Custom APT mirror (Kali Linux):
  symdis disasm \
      --debug-file libglib-2.0.so.0 \
      --debug-id D3C5EF14D63AF5AEB9C706A44E7AB2350 \
      --code-id 14efc5d33ad6aef5b9c706a44e7ab235f2358243 \
      --apt libglib2.0-0t64 --distro kali-rolling \
      --mirror https://http.kali.org/kali \
      --components main \
      --function g_main_context_iteration

  # Arch Linux pacman library (auto-detected via PROVIDES matching):
  symdis disasm \
      --debug-file libglib-2.0.so.0 \
      --debug-id 1B6047E8A0498E33A9C34903A2F9D12F0 \
      --code-id e847601b49a0338ea9c34903a2f9d12fcb011e98 \
      --pacman \
      --function g_main_context_iteration

  # Arch Linux pacman library (explicit package name):
  symdis disasm \
      --debug-file libglib-2.0.so.0 \
      --debug-id 1B6047E8A0498E33A9C34903A2F9D12F0 \
      --code-id e847601b49a0338ea9c34903a2f9d12fcb011e98 \
      --pacman glib2 \
      --function g_main_context_iteration

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

  # Skip .sym lookup and go straight to PDB (saves one round-trip
  # when you know .sym is unavailable; also pre-caches PDB for field-layout):
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

  - PREFER --socorro-json over manual flags. It extracts all module IDs,
    product, version, channel, distro, and backend flags automatically.
    Manual flags are a fallback when the full socorro JSON is not available.
  - When using manual flags, ALWAYS pass --code-file and --code-id from
    the crash report. Without them you usually get sym-only output (no
    disassembly). With them you get full annotated disassembly with source
    lines and call targets. (--socorro-json handles this automatically.)
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
    one round-trip when you know .sym is unavailable. For disassembly,
    the default .sym path gives better output (denser line coverage,
    consistent function names). For type information (field-layout),
    PDB is required — .sym files have no type data. For kernel
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
  - For system libraries (libxml2, mesa, libdrm, libffi, etc.) on
    Debian/Ubuntu, use --apt --distro <codename> to fetch binaries from
    APT packages. Supports Ubuntu (noble, jammy, ...) and Debian
    (bookworm, bullseye, ...) codenames. The source package name is
    auto-detected from .sym source paths (e.g., /build/libxml2-2gYHdD/...).
    Use --apt <package> to specify the binary package name explicitly
    when auto-detection fails. For other Debian derivatives (Kali, MX,
    Raspberry Pi OS), use --mirror to point to the custom repository.
  - For Arch Linux and derivatives (CachyOS, Manjaro, EndeavourOS),
    use --pacman to fetch binaries from pacman packages. The package
    is usually auto-detected (PROVIDES matching + name fallback).
    Use --pacman <pkg> to specify explicitly when auto-detect fails
    (mainly libc.so.6 → --pacman glibc). Use --mirror for derivative
    repos that use different mirrors. Arch is rolling release: only
    the latest package version is available, so older crashes may get
    sym-only output (build ID mismatch).
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

  NOTE: For modules without .sym files (e.g., kernel drivers, non-Mozilla
  Windows modules), use 'symdis disasm --function' or 'symdis disasm
  --offset' instead — it auto-falls back to PDB when .sym is unavailable.

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
  (from release info)    --distro        Release codename (e.g., noble, bookworm)
  (arch linux)           --pacman        Pacman package name (explicit or auto-detect)
  (from product name)    --product       firefox|thunderbird|fenix|focus (default: firefox)

  Pre-fetches the .sym file and native binary into the local cache so
  that subsequent disasm calls are instant cache hits. Useful when you
  plan to disassemble multiple functions from the same module. Always
  provide --code-file and --code-id to maximize binary fetch success.

  Binary fetch chain: cache → Tecken → Microsoft (Windows) → debuginfod
  (Linux) → Snap Store (Linux, --snap) → APT (Linux, --apt + --distro;
  supports Ubuntu + Debian) → pacman (Linux x86_64, --pacman; Arch Linux)
  → FTP archive (--version + --channel).

  For Linux modules, the full ELF build ID for debuginfod is extracted
  from the INFO CODE_ID record in the .sym file when --code-id is not
  provided.

  With --pdb, skips .sym and fetches PDB + binary instead. The PDB
  replaces the .sym (not the binary). PDB files are larger but contain
  type information (class/struct layouts) that .sym files lack — this
  enables 'symdis field-layout'. Sources for PDB: Tecken or
  Microsoft/Intel/AMD/NVIDIA symbol servers (Windows modules only,
  debug-file must end in .pdb). Reports type info availability for
  field-layout. For disassembly only, .sym is preferred (lighter,
  faster, denser line coverage).

  For Android crashes, --product fenix or --product focus is REQUIRED
  (it cannot be auto-detected because Android .sym files report OS as
  "Linux"). Binary fetch downloads the APK from Mozilla's FTP server
  and extracts the native library from lib/{abi}/ inside the APK.

  Note: snap and APT auto-detection from sym file source paths is only
  available in the disasm command. For fetch, use --snap, --apt
  <package>, or --pacman [package] explicitly.

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

  # Pre-fetch a Debian APT library:
  symdis fetch \
      --debug-file libglib-2.0.so.0 \
      --debug-id 958EC2424AF21D728E8E159F42DBC5410 \
      --code-id 42c28e95f24a721d8e8e159f42dbc541f0ff353d \
      --apt libglib2.0-0 --distro bookworm

  # Pre-fetch an Arch Linux pacman library:
  symdis fetch \
      --debug-file libglib-2.0.so.0 \
      --debug-id 1B6047E8A0498E33A9C34903A2F9D12F0 \
      --code-id e847601b49a0338ea9c34903a2f9d12fcb011e98 \
      --pacman

  # Fetch PDB + binary (skips .sym):
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
  (Tecken → Microsoft/Intel/AMD/NVIDIA → debuginfod → FTP archive).
  Works with any Windows module — PDB is fetched automatically when
  .sym is unavailable (kernel drivers, third-party DLLs, etc.).

  With --pdb, skips .sym and fetches PDB + binary instead. PDB files
  are heavier but contain type information (class/struct layouts) that
  .sym files lack — use this to check if 'symdis field-layout' will
  work for a module. Probes the TPI stream to report type info
  availability. Without --pdb, type info is reported only if the PDB
  is already in the local cache (no network cost). For disassembly
  only, .sym is preferred (lighter, faster, denser line coverage).

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

  # Fetch PDB + binary (skips .sym):
  symdis info \
      --debug-file ntdll.pdb \
      --debug-id 08A413EE85E91D0377BA33DC3A2641941 \
      --code-file ntdll.dll --code-id 5b6dddee267000 \
      --pdb

  # JSON output:
  symdis info \
      --debug-file xul.pdb \
      --debug-id EE20BD9ABD8D048B4C4C44205044422E1 \
      --code-file xul.dll --code-id 68d1a3cd87be000 \
      --format json

TIPS:

  - Run 'symdis info' before 'symdis disasm' to check whether the sym
    file and binary are available before attempting full disassembly.
  - For .pdb modules, use --pdb to fetch the PDB and check type info.
    When "field-layout available" is shown, 'symdis field-layout' will
    work for struct/class analysis. --pdb skips .sym fetch only. PDB is
    heavier than .sym but is required for type information; for
    disassembly, .sym is preferred (lighter, faster).
  - Provide --code-file and --code-id for accurate binary availability.
  - Use --version and --channel to check FTP archive fallback availability."#;

const FIELD_LAYOUT_LONG_HELP: &str = r#"PDB TYPE LAYOUT — FIELD-LEVEL ANALYSIS:

  Extracts the C++ class/struct/union field layout from PDB type information
  (TPI stream). This is PDB-only — .sym files do not contain type info.
  Type information is the key advantage PDB has over .sym files; for
  disassembly, .sym is preferred (lighter, faster, denser line coverage).

  Use this command to answer questions like "what field of nsFrameLoader is
  at offset 0x98?" when analyzing crash dumps. Unlike Searchfox's
  --field-layout (which only shows Linux x86_64 layouts), this uses the
  actual PDB from the crashed build, so offsets match the exact platform
  and build configuration.

  REQUIREMENTS:

    - The debug-file MUST be a .pdb file (e.g., xul.pdb, mozglue.pdb).
    - The PDB must contain type information (TPI stream). Mozilla PDBs
      (xul.pdb, mozglue.pdb) have full type data. Some Microsoft public
      symbol PDBs also include type info — e.g., ntdll.pdb has hundreds
      of types including _RTL_CRITICAL_SECTION, _PEB, _TEB, etc. Other
      Microsoft PDBs (kernel32.pdb, kernelbase.pdb) may have fewer or no
      types. Use 'symdis info' to check if a PDB has type information
      before running field-layout.
    - The --type argument is the C++ type name as it appears in PDB
      (e.g., "nsFrameLoader", "mozilla::dom::Element", "nsCOMPtr<nsIURI>").

  CRASH REPORT FIELD MAPPING:

    Socorro JSON field     CLI flag        Notes
    ---------------------  --------------  --------------------------------
    module.debug_file      --debug-file    Required. Must be .pdb
    module.debug_id        --debug-id      Required. 33-char hex string
    (from crash analysis)  --type          C++ type name to look up
    (from crash analysis)  --offset        Field offset from crash analysis

  OFFSET MATCHING:

    When --offset is provided, the output highlights the field that
    contains that byte offset with ==>. This helps identify which
    struct member was being accessed at a crash address.

    The matching logic: find the field where
      field.offset <= query < field.offset + field.size
    If the offset falls in a base class region and no field matches,
    the base class is highlighted instead.

  FUZZY SEARCH:

    With --fuzzy, --type performs substring matching on type names.
    If exactly one type matches, its layout is shown. If multiple
    match, they are listed (capped at 20) so you can refine.

  OUTPUT:

    Text output shows fields sorted by offset with type and name columns.
    JSON output (--format json) includes structured query_match when
    --offset is provided.

EXAMPLES:

  # Show layout of a Mozilla type from xul.pdb:
  symdis field-layout \
      --debug-file xul.pdb \
      --debug-id EE20BD9ABD8D048B4C4C44205044422E1 \
      --type nsFrameLoader

  # Find which field is at a specific offset:
  symdis field-layout \
      --debug-file xul.pdb \
      --debug-id EE20BD9ABD8D048B4C4C44205044422E1 \
      --type nsFrameLoader --offset 0x4c

  # Fuzzy search for a type name:
  symdis field-layout \
      --debug-file xul.pdb \
      --debug-id EE20BD9ABD8D048B4C4C44205044422E1 \
      --type FrameLoader --fuzzy

  # JSON output:
  symdis --format json field-layout \
      --debug-file xul.pdb \
      --debug-id EE20BD9ABD8D048B4C4C44205044422E1 \
      --type nsFrameLoader --offset 0x4c

  # Windows system type from ntdll.pdb (Microsoft public PDB has some types):
  symdis field-layout \
      --debug-file ntdll.pdb \
      --debug-id 08A413EE85E91D0377BA33DC3A2641941 \
      --type _RTL_CRITICAL_SECTION

TIPS:

  - Use 'symdis info' first to check if a PDB has type information.
    The output shows "field-layout available" with a type count when
    TPI data is present, or "no type info (stripped/public PDB)" when
    the TPI stream is empty.
  - This command works with any PDB that has type info, not just
    Mozilla PDBs. Some Microsoft public symbol PDBs include type
    data — e.g., ntdll.pdb has hundreds of Windows kernel types
    (_RTL_CRITICAL_SECTION, _PEB, _TEB, _HEAP, etc.). Third-party
    vendor PDBs with full debug info also work.
  - For Mozilla modules, the PDB is fetched from Tecken or symbol
    servers (same fetch chain as --pdb in disasm). Large PDBs like
    xul.pdb may take several minutes to download on first use.
  - Type names in PDB are undemangled C++ names. Use the exact name
    as MSVC knows it (e.g., "nsTArray<int>" not "nsTArray<int32_t>").
    When in doubt, use --fuzzy for substring matching.
  - Virtual function table pointers appear as <vfptr> fields at the
    start of classes with virtual methods.
  - Anonymous structs/unions are flattened by PDB — their fields
    appear at the correct offsets but grouping is lost."#;

#[derive(Parser)]
#[command(
    name = "symdis",
    version,
    about = "Symbolic disassembler for Mozilla crash report analysis",
    long_about = "Symbolic disassembler for crash report analysis.\n\n\
        Designed for AI agents analyzing crash reports. Given a module's \
        debug identifiers and a function name or offset, symdis fetches \
        symbols and binaries from symbol servers (Mozilla Tecken, Microsoft, \
        Intel, AMD, NVIDIA, debuginfod) and produces annotated disassembly \
        with source lines, call targets, and inline frames.\n\n\
        Supports Windows (PE), Linux (ELF), macOS (Mach-O), and Android \
        modules. Not limited to Mozilla — works with any module from a \
        crash report, including Microsoft system DLLs, Windows kernel \
        drivers, GPU drivers, Linux system libraries, and macOS frameworks. \
        PDB files are fetched automatically when .sym is unavailable.\n\n\
        Subcommands:\n  \
        disasm        Disassemble a function (primary command)\n  \
        lookup        Resolve offset → symbol or symbol → address (sym file only)\n  \
        info          Show module metadata and PDB type info availability\n  \
        fetch         Pre-fetch symbols and binary into cache\n  \
        field-layout  Show C++ class/struct field layout from PDB type info\n  \
        cache         Manage the local cache (path, size, clear, list)\n\n\
        Update check:\n  \
        On each run, symdis checks crates.io in the background for a newer\n  \
        version. If one is found, a notice is printed to stderr after the\n  \
        command completes. The check is cached for 24 hours and can be\n  \
        disabled by setting MOZTOOLS_UPDATE_CHECK=0.\n\n\
        Machine-readable output:\n  \
        All diagnostic messages (tracing, update notices) go to stderr.\n  \
        JSON output (--format json) goes to stdout. Do not merge stdout\n  \
        and stderr when parsing JSON output programmatically."
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
    /// Show module metadata and PDB type info availability
    Info(InfoArgs),
    /// Pre-fetch symbols and binary for a module
    Fetch(FetchArgs),
    /// Show C++ class/struct field layout from PDB type information
    #[command(name = "field-layout")]
    FieldLayout(FieldLayoutArgs),
    /// Manage the local cache
    Cache(CacheArgs),
}

#[derive(Parser)]
#[command(
    before_help = DISASM_BEFORE_HELP,
    before_long_help = DISASM_BEFORE_LONG_HELP,
    after_long_help = DISASM_AFTER_LONG_HELP
)]
pub struct DisasmArgs {
    /// Debug file name (e.g., xul.pdb, libxul.so)
    #[arg(long, required_unless_present = "socorro_json")]
    pub debug_file: Option<String>,

    /// Debug identifier (33-character hex string)
    #[arg(long, required_unless_present = "socorro_json")]
    pub debug_id: Option<String>,

    /// Socorro crash report JSON file path, or "-" for stdin.
    /// Auto-extracts debug-file, debug-id, code-file, code-id, offset,
    /// version, channel, product, and distro from the crash report.
    /// Explicit CLI flags override auto-extracted values.
    #[arg(long)]
    pub socorro_json: Option<String>,

    /// Frame index in the crashing thread (0 = top/crash frame).
    /// Only used with --socorro-json.
    #[arg(long, default_value = "0")]
    pub frame: usize,

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

    /// Enable APT backend for system libraries. Optionally specify
    /// the binary package name; if omitted, the source package name is
    /// auto-detected from sym file source paths.
    #[arg(long, num_args = 0..=1, default_missing_value = "")]
    pub apt: Option<String>,

    /// Distribution release codename (e.g., noble, bookworm). Required with --apt.
    #[arg(long)]
    pub distro: Option<String>,

    /// Override APT mirror URL (e.g., https://archive.raspberrypi.com/debian).
    /// When set, --distro must still be provided for the release codename.
    #[arg(long)]
    pub mirror: Option<String>,

    /// Override APT components (comma-separated, e.g., "main,contrib").
    /// Only used with --mirror. Default: "main".
    #[arg(long)]
    pub components: Option<String>,

    /// Enable pacman backend for Arch Linux packages. Optionally specify
    /// the package name; if omitted, auto-detects via PROVIDES matching.
    /// Use --mirror to override the default Arch mirror.
    #[arg(long, num_args = 0..=1, default_missing_value = "")]
    pub pacman: Option<String>,

    /// Mozilla product: firefox (default), thunderbird, fenix, or focus.
    /// For Android crashes, you MUST specify --product fenix or --product focus.
    /// It cannot be auto-detected (Android .sym files report OS as "Linux").
    #[arg(long, default_value = "firefox")]
    pub product: String,

    /// Prefer PDB over .sym file for symbol data (heavier but has type info).
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

    /// Also fetch PDB file from symbol servers and probe for type information.
    /// PDB is heavier than .sym but has type info for field-layout.
    /// Only applicable to Windows modules (debug-file ends in .pdb).
    #[arg(long)]
    pub pdb: bool,
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

    /// Enable APT backend for system libraries. Optionally specify
    /// the binary package name; if omitted, requires source package name from
    /// sym file source paths.
    #[arg(long, num_args = 0..=1, default_missing_value = "")]
    pub apt: Option<String>,

    /// Distribution release codename (e.g., noble, bookworm). Required with --apt.
    #[arg(long)]
    pub distro: Option<String>,

    /// Override APT mirror URL (e.g., https://archive.raspberrypi.com/debian).
    /// When set, --distro must still be provided for the release codename.
    #[arg(long)]
    pub mirror: Option<String>,

    /// Override APT components (comma-separated, e.g., "main,contrib").
    /// Only used with --mirror. Default: "main".
    #[arg(long)]
    pub components: Option<String>,

    /// Enable pacman backend for Arch Linux packages. Optionally specify
    /// the package name; if omitted, requires PROVIDES matching against
    /// the binary's soname (no auto-detection from sym file in fetch).
    #[arg(long, num_args = 0..=1, default_missing_value = "")]
    pub pacman: Option<String>,

    /// Mozilla product: firefox (default), thunderbird, fenix, or focus.
    /// For Android crashes, you MUST specify --product fenix or --product focus.
    /// It cannot be auto-detected (Android .sym files report OS as "Linux").
    #[arg(long, default_value = "firefox")]
    pub product: String,

    /// Also fetch PDB file from symbol servers (heavier but has type info).
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

#[derive(Parser)]
#[command(after_long_help = FIELD_LAYOUT_LONG_HELP)]
pub struct FieldLayoutArgs {
    /// Debug file name (must be a .pdb file)
    #[arg(long)]
    pub debug_file: String,

    /// Debug identifier (33-character hex string)
    #[arg(long)]
    pub debug_id: String,

    /// C++ type name to look up
    #[arg(long = "type")]
    pub type_name: String,

    /// Enable substring matching for --type
    #[arg(long)]
    pub fuzzy: bool,

    /// Highlight the field at this byte offset (hex, with or without 0x prefix)
    #[arg(long)]
    pub offset: Option<String>,
}

/// Context for generating actionable hints when binary fetch fails.
pub struct HintContext<'a> {
    pub debug_file: &'a str,
    pub is_linux: bool,
    pub effective_code_id: Option<&'a str>,
    pub code_file_provided: bool,
    pub code_id_provided: bool,
    pub version_provided: bool,
    pub channel_provided: bool,
    pub apt_enabled: bool,
    pub pacman_enabled: bool,
    pub snap_provided: bool,
    pub product: &'a str,
    pub is_socorro_mode: bool,
    pub sym_arch: Option<&'a str>,
}

/// Generate actionable one-liner hints for binary fetch failures.
///
/// Each hint fires only when the corresponding flag wasn't already set and the
/// hint is actionable. All hints are suppressed in `--socorro-json` mode
/// (which auto-extracts most flags).
pub fn generate_binary_fetch_hints(ctx: &HintContext) -> Vec<String> {
    if ctx.is_socorro_mode {
        return Vec::new();
    }

    let mut hints = Vec::new();

    // Rule A: no --code-file AND no --code-id
    if !ctx.code_file_provided && !ctx.code_id_provided {
        hints.push(
            "pass --code-file and --code-id from the crash report for better binary fetch results"
                .to_string(),
        );
    }

    // Rule B: Linux module, no --apt, no --pacman, no --snap
    if ctx.is_linux && !ctx.apt_enabled && !ctx.pacman_enabled && !ctx.snap_provided {
        hints.push(
            "try --apt --distro <codename> (Debian/Ubuntu), --pacman (Arch Linux), \
             or --snap <name> (Ubuntu snap). Package names are usually auto-detected \
             but some need an explicit name (e.g. libc.so.6 needs --apt glibc or --pacman glibc)"
                .to_string(),
        );
    }

    // Rule C: no --version or no --channel
    if !ctx.version_provided || !ctx.channel_provided {
        hints.push(
            "pass --version and --channel to try Mozilla FTP archive \
             (also --build-id for nightly builds)"
                .to_string(),
        );
    }

    // Rule D: Linux + ARM/AArch64 .so + product is "firefox" (default)
    if ctx.is_linux && ctx.product == "firefox" {
        let is_arm = ctx.sym_arch.is_some_and(|a| {
            a.eq_ignore_ascii_case("arm")
                || a.eq_ignore_ascii_case("arm64")
                || a.eq_ignore_ascii_case("aarch64")
                || a.eq_ignore_ascii_case("armv7l")
        });
        if is_arm {
            hints.push(
                "for Android/Fenix crashes, add --product fenix or --product focus".to_string(),
            );
        }
    }

    // Rule E: .pdb debug file, no --code-file, derived code file is .dll
    if !ctx.code_file_provided {
        let lower = ctx.debug_file.to_ascii_lowercase();
        if lower.ends_with(".pdb") {
            let stem = &ctx.debug_file[..ctx.debug_file.len() - 4];
            if !stem.eq_ignore_ascii_case("firefox") {
                // Default heuristic derives .dll — hint about .sys
                hints.push(format!(
                    "for .sys kernel drivers, pass --code-file {}.sys explicitly \
                     (the default heuristic derives .dll)",
                    stem,
                ));
            }
        }
    }

    // Rule G: version+channel provided but product is still "firefox" (default)
    // Could be a Thunderbird crash where the FTP archive URL is wrong.
    if ctx.version_provided && ctx.channel_provided && ctx.product == "firefox" {
        hints.push("if this is a Thunderbird crash, add --product thunderbird".to_string());
    }

    // Rule F: Linux module, no effective code_id
    if ctx.is_linux && ctx.effective_code_id.is_none() {
        hints.push(
            "pass --code-id (full ELF build ID, 40 hex chars) to enable debuginfod \
             and other Linux binary fetch sources"
                .to_string(),
        );
    }

    hints
}

pub async fn run(cli: Cli) -> Result<()> {
    let config = Config::resolve(&cli)?;

    match cli.command {
        Command::Disasm(ref args) => {
            if args.function.is_none() && args.offset.is_none() && args.socorro_json.is_none() {
                bail!("Either --function, --offset, or --socorro-json must be specified");
            }
            disasm::run(args, &config).await
        }
        Command::Lookup(ref args) => {
            if args.function.is_none() && args.offset.is_none() {
                bail!("Either --function or --offset must be specified");
            }
            lookup::run(args, &config).await
        }
        Command::Info(ref args) => info::run(args, &config).await,
        Command::Fetch(ref args) => fetch::run(args, &config).await,
        Command::FieldLayout(ref args) => field_layout::run(args, &config).await,
        Command::Cache(args) => cache_cmd::run(args, &config),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_context<'a>() -> HintContext<'a> {
        HintContext {
            debug_file: "libxul.so",
            is_linux: true,
            effective_code_id: None,
            code_file_provided: false,
            code_id_provided: false,
            version_provided: false,
            channel_provided: false,
            apt_enabled: false,
            pacman_enabled: false,
            snap_provided: false,
            product: "firefox",
            is_socorro_mode: false,
            sym_arch: None,
        }
    }

    #[test]
    fn test_socorro_mode_suppresses_all_hints() {
        let mut ctx = base_context();
        ctx.is_socorro_mode = true;
        let hints = generate_binary_fetch_hints(&ctx);
        assert!(hints.is_empty());
    }

    #[test]
    fn test_rule_a_no_code_file_no_code_id() {
        let ctx = base_context();
        let hints = generate_binary_fetch_hints(&ctx);
        assert!(hints.iter().any(|h| h.contains("--code-file")));
    }

    #[test]
    fn test_rule_a_suppressed_when_code_file_provided() {
        let mut ctx = base_context();
        ctx.code_file_provided = true;
        ctx.code_id_provided = true;
        let hints = generate_binary_fetch_hints(&ctx);
        assert!(!hints.iter().any(|h| h.contains("--code-file")));
    }

    #[test]
    fn test_rule_b_linux_no_backends() {
        let ctx = base_context();
        let hints = generate_binary_fetch_hints(&ctx);
        assert!(hints.iter().any(|h| h.contains("--apt")));
    }

    #[test]
    fn test_rule_b_suppressed_when_apt_enabled() {
        let mut ctx = base_context();
        ctx.apt_enabled = true;
        let hints = generate_binary_fetch_hints(&ctx);
        assert!(!hints.iter().any(|h| h.contains("--apt")));
    }

    #[test]
    fn test_rule_b_suppressed_for_windows() {
        let mut ctx = base_context();
        ctx.is_linux = false;
        ctx.debug_file = "xul.pdb";
        let hints = generate_binary_fetch_hints(&ctx);
        assert!(!hints.iter().any(|h| h.contains("--apt")));
    }

    #[test]
    fn test_rule_c_no_version_no_channel() {
        let ctx = base_context();
        let hints = generate_binary_fetch_hints(&ctx);
        assert!(hints.iter().any(|h| h.contains("--version")));
    }

    #[test]
    fn test_rule_c_suppressed_when_both_provided() {
        let mut ctx = base_context();
        ctx.version_provided = true;
        ctx.channel_provided = true;
        let hints = generate_binary_fetch_hints(&ctx);
        assert!(!hints.iter().any(|h| h.contains("--version")));
    }

    #[test]
    fn test_rule_d_linux_arm_firefox() {
        let mut ctx = base_context();
        ctx.sym_arch = Some("arm");
        let hints = generate_binary_fetch_hints(&ctx);
        assert!(hints.iter().any(|h| h.contains("--product fenix")));
    }

    #[test]
    fn test_rule_d_suppressed_for_non_arm() {
        let mut ctx = base_context();
        ctx.sym_arch = Some("x86_64");
        let hints = generate_binary_fetch_hints(&ctx);
        assert!(!hints.iter().any(|h| h.contains("--product fenix")));
    }

    #[test]
    fn test_rule_d_suppressed_for_non_firefox_product() {
        let mut ctx = base_context();
        ctx.sym_arch = Some("arm64");
        ctx.product = "fenix";
        let hints = generate_binary_fetch_hints(&ctx);
        assert!(!hints.iter().any(|h| h.contains("--product fenix")));
    }

    #[test]
    fn test_rule_e_pdb_no_code_file() {
        let mut ctx = base_context();
        ctx.is_linux = false;
        ctx.debug_file = "ntoskrnl.pdb";
        let hints = generate_binary_fetch_hints(&ctx);
        assert!(hints.iter().any(|h| h.contains(".sys")));
    }

    #[test]
    fn test_rule_e_suppressed_when_code_file_provided() {
        let mut ctx = base_context();
        ctx.is_linux = false;
        ctx.debug_file = "ntoskrnl.pdb";
        ctx.code_file_provided = true;
        let hints = generate_binary_fetch_hints(&ctx);
        assert!(!hints.iter().any(|h| h.contains(".sys")));
    }

    #[test]
    fn test_rule_e_suppressed_for_firefox_pdb() {
        let mut ctx = base_context();
        ctx.is_linux = false;
        ctx.debug_file = "firefox.pdb";
        let hints = generate_binary_fetch_hints(&ctx);
        // firefox.pdb derives .exe not .dll, so hint about .sys is not useful
        assert!(!hints.iter().any(|h| h.contains(".sys")));
    }

    #[test]
    fn test_rule_f_linux_no_code_id() {
        let ctx = base_context();
        let hints = generate_binary_fetch_hints(&ctx);
        assert!(hints.iter().any(|h| h.contains("debuginfod")));
    }

    #[test]
    fn test_rule_f_suppressed_when_code_id_present() {
        let mut ctx = base_context();
        ctx.effective_code_id = Some("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2");
        let hints = generate_binary_fetch_hints(&ctx);
        assert!(!hints.iter().any(|h| h.contains("debuginfod")));
    }

    #[test]
    fn test_rule_g_version_channel_default_product() {
        let mut ctx = base_context();
        ctx.version_provided = true;
        ctx.channel_provided = true;
        let hints = generate_binary_fetch_hints(&ctx);
        assert!(hints.iter().any(|h| h.contains("--product thunderbird")));
    }

    #[test]
    fn test_rule_g_suppressed_when_product_not_firefox() {
        let mut ctx = base_context();
        ctx.version_provided = true;
        ctx.channel_provided = true;
        ctx.product = "thunderbird";
        let hints = generate_binary_fetch_hints(&ctx);
        assert!(!hints.iter().any(|h| h.contains("--product thunderbird")));
    }

    #[test]
    fn test_rule_g_suppressed_when_no_version() {
        let ctx = base_context();
        // version_provided = false, channel_provided = false
        let hints = generate_binary_fetch_hints(&ctx);
        assert!(!hints.iter().any(|h| h.contains("--product thunderbird")));
    }

    #[test]
    fn test_all_flags_provided_no_hints() {
        let mut ctx = base_context();
        ctx.code_file_provided = true;
        ctx.code_id_provided = true;
        ctx.version_provided = true;
        ctx.channel_provided = true;
        ctx.apt_enabled = true;
        ctx.product = "thunderbird"; // explicit product suppresses Rule G
        ctx.effective_code_id = Some("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2");
        let hints = generate_binary_fetch_hints(&ctx);
        assert!(hints.is_empty());
    }
}
