# v0.8 changes: the exposure capability (the defensive mirror of REA)

A reverse-engineering tool (REA-class) takes a shipped build apart across ~30 formats. v0.8 adds the
defensive mirror: **exposure**, which answers a launcher's question about their *own* release —

> If someone ran a REA-class tool on my build, what would they recover, which of it can I avoid, and
> what exactly do I change?

It is **additive and advisory**. It plugs in three ways — a CLI command (`anti-rea expose`), a GitHub
Action and an MCP server — and it is static, read-only, in-memory, and makes no network calls. It trips
**no gate**: the release decision path (`assure`, `engine/gate.ts`, `engine/evaluate.ts`) is untouched by
construction (the recovery lane is never run by `assure`).

The scope line is unchanged from v0.7: Anti-REA assures releases against reverse-engineering *aids*. It
does not build obfuscation, packing or anti-debug, and it never claims an app "cannot be reverse
engineered". Remediation points to standard toolchain settings; third-party obfuscators are named only
where the exposure is inherent to the platform, with their tradeoffs.

## 1. What it reports

`anti-rea expose <path>` is zero-config: `<path>` may be a `.app`, an `.apk`/`.ipa`/`.exe`, a directory
or a single file. It builds a minimal manifest in memory (the inventory builder now exposes
`inventoryOfPath`; directory behaviour is unchanged and still covered by the existing tests) and infers
the app name/version from `Info.plist` or `package.json`. `--manifest` still works for a declared closure.

It writes `exposure.json` (schema `anti-rea/exposure/v1`) and `exposure.md`: a product profile (detected
platforms, frameworks, languages), an executive summary, findings by attack surface with **owner code
first and third-party collapsed into counts**, a deduplicated hardening checklist (one action, its files,
its grade), coverage with every opaque artifact named, and the REA → Anti-REA matrix. Output is
deterministic (sorted, honours `--now`).

## 2. The rubric (grades are fixed by attack surface)

Analyzers never invent a grade: each names a **rubric row** ([src/analyzers/rubric.ts](../../src/analyzers/rubric.ts)),
which fixes the attack surface and the severity (reusing the repo's `Severity`). Every finding also
carries `avoidable` (a toolchain setting removes it) vs inherent, and `origin` (owner vs third-party).

| Surface | critical | high | medium | low | info |
|---|---|---|---|---|---|
| Code recoverability | source text (sourcesContent, `.py`/GDScript, Mono `Assembly-CSharp`) | near-source bytecode/IL (.NET IL, `.pyc`, DEX w/o R8) | | | |
| Symbols & structure | | DWARF/dSYM/PDB, stabs, IL2CPP metadata in the clear, WASM name+DWARF | local symbols, ELF `.symtab`, WASM name only | | ObjC/Swift metadata, Go `pclntab` |
| Build & supply-chain | | | | build paths, Go modules/VCS, cargo-auditable, PDB path | |
| Tamper & debug resistance | | `debuggable`, `get-task-allow`, insecure Electron `webPreferences` | unsigned, APK v1-only, fuses off, DevTools | | |
| Exploit mitigations | | | no PIE/NX/CFG on owner C/C++ | partial RELRO; Go/Rust defaults | |
| Model/asset disclosure | | | plaintext safetensors/GGUF metadata | | |

`--fail-on` and the Action's `max-grade` use the **maximum** grade — never an aggregate score — so a
critical can't be averaged away (research §10.1 still holds).

## 3. One source of truth, and owner vs third-party

v0.7 already reads DWARF, stabs, locals, source maps, sources, signing, entitlements and fuses. v0.8
**adapts** those fact collectors (`collectAidsFacts`, `collectPlatformFacts`, the symbol and Mach-O
readers) rather than re-detecting, so each fact has one source of truth. New parsers were added only for
new formats: [pe.ts](../../src/codecs/pe.ts) (closing the README gap "no PE debug-directory parsing" for
the exposure report), [elf.ts](../../src/codecs/elf.ts), [axml.ts](../../src/codecs/axml.ts), and
per-analyzer readers for IL2CPP, DEX, APK signing blocks, GGUF/safetensors, Godot PCK, WASM, PTX/fatbin,
Go buildinfo, cargo-auditable and the PyInstaller cookie.

Every finding is attributed owner vs third-party by path ([attribution.ts](../../src/analyzers/attribution.ts)):
the release-root label itself is never treated as a path segment; `node_modules`, vendored runtimes (Electron Framework, Sparkle, ffmpeg, Lottie, Chromium blobs, the
MSVC/UCRT redistributables, the .NET shared runtime, Unity/Flutter engines) (matched by exact file or bundle name, never by prefix), and sibling frameworks whose bundle id does not
share the app's reverse-DNS prefix. `flutter_assets` is the app's own output, not the engine. In v0.7 calibration most native signal was third-party; owner findings
now rank first and third-party collapses into counts.

## 4. Language- and platform-aware grading (known false-lead classes)

- Go and Rust are memory-safe, so **no stack-canary or FORTIFY findings** are raised for them.
- Go `linux/amd64` defaults to non-PIE with no RELRO; that is graded **low and inherent to the toolchain**,
  not as an owner C/C++ mitigation gap.
- Go `pclntab` function names survive `-s -w`; reported as **inherent** (garble named as a third-party
  tradeoff).
- `LC_ENCRYPTION_INFO cryptid=0` is graded only for iOS App Store slices (`LC_BUILD_VERSION` platform),
  never for macOS.
- A stripped Mach-O keeps a leftover `N_SO` stab with no objects/sources (seen on `/bin/ls`); a debug map
  is only reported when it actually names object or source files.

## 5. Redaction invariant

The report must not become the leak. Build metadata is the live hazard: Go buildinfo records the exact
`-ldflags`, so `-X importpath.key=<secret>` would otherwise land verbatim in `exposure.json`.
[redact.ts](../../src/analyzers/redact.ts) masks the value of `-X` assignments, credential-named
`KEY=VALUE` pairs and high-entropy blobs, keeping a non-reconstructible preview. GGUF and safetensors
print metadata **keys** and the architecture name only, never values. Tests assert a planted `-X` secret
and a planted safetensors `__metadata__` secret never appear in the serialized report; the differential
test confirms the oracle (`go version -m`) *does* show the secret, so redaction is doing real work.

## 6. Robustness and tests

Every analyzer runs in `try/catch` in the recovery lane; a failure becomes a coverage note, never a
crash. Every reader bounds-checks each offset and caps every loop (a GGUF can claim 2^63 KV pairs; a DEX
can claim billions of types). Header-only analyzers (GGUF, safetensors) also run on size-limit **gap**
items via positioned reads, so a multi-GB model still gets a header verdict with `coverage: partial`.

- **Units/pipeline/golden/redaction** ([test/v08.test.ts](../../test/v08.test.ts)): the rubric,
  attribution, redaction, every per-format analyzer (with spec-cited hand-made fixtures, including a
  from-scratch binary AndroidManifest), the exposure report shape, and the load-bearing invariant that
  **every recovery finding is gate-free**.
- **Differential** ([test/v08-differential.test.ts](../../test/v08-differential.test.ts)): Go buildinfo
  vs `go version -m`, Mach-O PIE vs `otool -hv`, stripping removing local symbols. Skips when the tool is
  absent.
- **Fuzz** ([test/v08-fuzz.test.ts](../../test/v08-fuzz.test.ts)): ~10,000 seeded truncate/bit-flip/
  randomise corruptions across the readers; no exception escapes and each run finishes within a time
  bound. A second, structure-preserving fuzzer ([test/v08-review.test.ts](../../test/v08-review.test.ts))
  mutates complete valid fixtures in place (a PE with a CodeView record, an APK signing block, Go
  buildinfo, ELF, and the system's own Mach-O binaries), so the deep parser paths run with hostile values.
- **Review regressions** ([test/v08-review.test.ts](../../test/v08-review.test.ts)): one test per defect
  found in the pre-commit review (section 9).

Total suite: 150 tests (108 pre-existing, unchanged), all passing.

## 7. Calibration (tuning data only — no accuracy or superiority claims)

Per the project's benchmark discipline, this is **tuning data only**: no accuracy or superiority claims,
no benchmark this pass, the spent sets stay untouched and the v6 evaluation is **not** re-run. A
pre-registered v7 exposure benchmark on fresh, unseen real code is future work.

Observed on installed apps (`/Applications`, Homebrew Go/Rust binaries, `~/.cargo/bin`):

- **Ghostty.app** — the main `ghostty` binary genuinely ships a ~70k-entry stabs debug map (build paths)
  plus local symbols and ObjC/Swift metadata; the vendored Sparkle/updater frameworks were correctly
  split out as third-party. The initial app-name heuristic picked a nested `Updater.app`; fixed to the
  outermost bundle.
- **`/bin/ls`** — a stripped system binary surfaced a spurious stabs "debug map" with 0 objects/0 sources
  (a leftover `N_SO`); the analyzer now requires real object/source names, so `/bin/ls` is clean.
- **`gh` (Go), `~/.cargo/bin` (Rust)** — native local-symbol findings (medium) dominate, which is accurate
  (unstripped release binaries) and is handled by the owner-first ordering and the deduplicated checklist;
  a Go `.exe` was briefly mislabeled C/C++ (native-pe no longer asserts a source language).

No crashes, no critical false positives, and the arm64/arm64e fat-slice pair is no longer double-reported.

## 8. Distribution

- **MCP server** ([src/mcp/server.ts](../../src/mcp/server.ts)): hand-rolled, **zero-dependency**,
  newline-delimited JSON-RPC over stdio, including batches. `initialize` negotiates protocol (2025-06-18 / 2025-03-26 /
  2024-11-05); `tools/list`, `tools/call` (with `structuredContent` and `isError`) and `ping`. Logs go to
  stderr; stdout carries only JSON-RPC. Tools: `expose_release`, `inventory`, `inspect`,
  `analyze_artifact` (the full recovery lane over one file, so an .apk/.ipa is expanded). Results carry
  `structuredContent` plus the same JSON as a text block for older clients; `expose_release` lists owner
  findings only unless `includeThirdParty`. It refuses the filesystem root and the home directory. Read-only. Bin `anti-rea-mcp`; `anti-rea mcp-config` prints registration snippets.
- **GitHub Action** ([action.yml](../../action.yml)): composite (`uses: <owner>/anti-rea@v0.8.0`); builds,
  runs `expose`, appends the Markdown to `$GITHUB_STEP_SUMMARY`, uploads the Markdown and JSON (actions pinned by
  SHA), and optionally fails on `fail-on`. Inputs reach the scripts only as environment variables, never
  interpolated into them, so a path cannot inject shell. The repo has no remote, so this is checked locally (YAML lint + the
  same steps in a shell), not on GitHub. Example: [examples/workflows/exposure.yml](../../examples/workflows/exposure.yml).
- **[docs/AGENTS.md](../AGENTS.md)**: a short agent workflow, mirroring REA's agent setup.

## 9. Pre-commit review fixes

A review of the whole v0.8 diff before the first commit found and fixed these. Each has a regression test
in [test/v08-review.test.ts](../../test/v08-review.test.ts) or was checked by hand as noted.

- **APK signing**: v2/v3-signed APKs were reported unsigned (the signing-block pairs were read from the
  wrong offset). v1 now needs both a signature file (`.RSA/.DSA/.EC`) and its `.SF`; an AAB gets no
  signing verdict. R8 state is "undecidable" below 20 defined classes instead of guessed.
- **PE**: `readPe` reversed the RSDS GUID in place, mutating the caller's buffer (and the next read gave
  a different GUID). Bounds checks added to the CLR and section lookups. Go and Rust PE gaps are graded
  as toolchain limits (Go has no CFG), not owner omissions.
- **Mach-O**: LC_VERSION_MIN codes for tvOS/watchOS were wrong (0x26/0x27 are other commands), arm64e was
  mislabelled, `MH_NO_HEAP_EXECUTION` was misread; executable stacks are now reported. Runtime metadata is
  matched to its own slice in fat binaries.
- **AXML**: a truncated or hostile chunk header threw "offset out of range"; the reader is now bounds-safe.
- **Attribution**: the release-root label was matched as a path segment (a release folder named
  `vendor` became all third-party); vendor names are exact, and bundle-id prefixes decide helpers.
- **Electron**: `process.versions` passed to `exposeInMainWorld` was flagged as wholesale exposure;
  `{ ipcRenderer }` objects were missed. Electron detection now needs Electron APIs, not the word.
- **PyInstaller**: the bootloader's own magic constant could be taken for the cookie; the cookie is now
  found from the end, as PyInstaller does, and the TOC is read for entry scripts.
- **Go**: a binary carrying the buildinfo magic as a string constant could hide its real header; every
  occurrence is tried. Pre-1.18 buildinfo is reported detected-only.
- **ELF**: CUDA/AMDGPU device code, object files and core dumps were graded as host executables.
- **Debug files**: the v0.7 aids adapter was replaced by a `debug-files` analyzer that reuses the aids
  lane's classifiers directly (one source of truth, owner attribution).
- **Report**: Markdown escaping now covers `|`, newlines, `<`, `>` and link syntax, so artifact names
  cannot inject table cells, HTML or links.
- **CLI**: `expose` validates `--fail-on`/`--out` before the walk and refuses to write its report inside
  the directory it inspects (the next run would scan it); `inspect` now includes the recovery findings.
- **GitHub Action**: env vars were passed after `node -e` as arguments, so outputs and the summary were
  never written and `fail-on` never failed the job; inputs were interpolated straight into the script.
  Fixed and checked by running the same steps in a shell with `GITHUB_OUTPUT`/`GITHUB_STEP_SUMMARY` set
  (advisory, threshold met, a path containing shell syntax, an invalid severity).
- **MCP**: see section 8; checked with a scripted exchange (initialize, notification, batch, each tool,
  root refusal, invalid request, parse error).
