# Contributing to symdis

## Getting Started

```bash
git clone https://github.com/yjugl/symdis.git
cd symdis
cargo build
cargo test
cargo clippy -- -D warnings
```

All tests must pass and clippy must report zero warnings before submitting changes.

## AI Tool Usage

This project was developed with AI assistance and follows Mozilla's [AI and Coding](https://firefox-source-docs.mozilla.org/contributing/ai-coding.html) policy. Key points:

- **Accountability**: You are accountable for all changes you submit, regardless of the tools you use.
- **Understanding**: You must understand and be able to explain every change you submit.
- **Quality**: Contributions must meet the same standards of correctness, security, and maintainability as any other patch.
- **Data protection**: Do not include private, security-sensitive, or otherwise confidential information in prompts to external AI tools.

## Data Privacy

symdis is designed to process only **publicly available data** from crash reports. All inputs — module identifiers, stack trace offsets, function names, and release metadata — come from the public portions of [Crash Stats](https://crash-stats.mozilla.org/) reports. The tool fetches symbol files and binaries from public servers only.

When contributing, follow these guidelines:

- Do not add features that process or store [protected crash report data](https://crash-stats.mozilla.org/documentation/protected_data_access/) such as minidumps, memory contents, user comments, email addresses, or URLs from crash annotations.
- New inputs should be limited to publicly available crash report fields (module identifiers, stack trace offsets, function names, release metadata).
- If a future feature requires accessing the Socorro API, it must extract only publicly available fields and must not store, log, or forward protected fields.

## License

This project is licensed under the [Mozilla Public License 2.0](LICENSE). All new `.rs` source files must include the MPL 2.0 header:

```rust
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
```
