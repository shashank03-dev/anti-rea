# Changelog

## 0.1.0 — first public release

Published on npm as **`@anti-rea/cli`** (npm reserves names close to existing packages; `anti-rea` is too close to `antirea`). The commands are `anti-rea` and `anti-rea-mcp`.

The internal development milestones v0.1–v0.8 ([docs/research/](docs/research/)) precede this release.

### Added

- **`anti-rea init <dist>`** scaffolds `anti-rea.manifest.json` and `anti-rea.policy.json` from what the build
  contains. Platform expectations (macOS signing and hardened runtime, Electron fuses, ASAR integrity, Authenticode)
  are declared only when the build has code they apply to.
- **Exposure report:** DWARF and COFF symbol tables in PE images (MinGW, Go), and inline `data:` source maps.
- **`--version` / `-v`.**
- The **v7 benchmark** of the exposure report: pre-registered, run once, on real toolchain builds
  ([bench/v7/](bench/v7/)).
- CI on Linux, macOS and Windows × Node 22/24/26; an install smoke test of the packed tarball; a tag-triggered
  release workflow.

### Fixed

- The exposure report missed source maps larger than 1 MiB, the ones that ship the most source, because bundlers
  write `sourcesContent` before `mappings`. It also skipped Electron main bundles larger than 1 MiB. Both now read
  the whole file.
- Bundled Chrome Web Store extensions (for example React DevTools inside an Electron app) are attributed to third
  parties instead of setting the owner grade.
- Block messages for inconclusive lanes say why and name the exception that unblocks them. Uninspectable files
  are named. Duplicate per-architecture locations are collapsed.
- Windows-style manifest roots (`release\App`) label items exactly like posix roots.
- OLE compound files are reported as "MSI installer or legacy Office", not as MSI.

### Changed

- Requires Node ≥ 22. Node 20 reached end-of-life in April 2026.
- Proprietary license ([LICENSE](LICENSE)).
