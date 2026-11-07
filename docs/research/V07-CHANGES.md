# v0.7 changes: the reverse-engineering-aids lane

Protection can't make shipped code unrecoverable. What a release *can* avoid is handing a reverse engineer what the build already knew how to remove:

- debug information;
- debug maps with build paths;
- internal symbol names;
- source maps and original sources;
- unminified code;
- an Electron renderer with isolation switched off.

v0.7 adds a lane that reads these facts from the shipped bytes and a gate that blocks on them. Every native fact is checked against the platform's own tools. The JavaScript classifier was fitted on one half of a labelled corpus and evaluated on the other half. It was then calibrated on nine installed apps and evaluated once on a sealed third-party tree.

## 1. What the lane checks (`manifest.reAids`, lane `aids`, gate `reverseEngineeringAidShipped`)

Declaring `reAids: {}` runs checks 1–3 with their defaults. Checks 4 and 5 are opt-in. Any check can be set to `false`.

| Check | Reports | Default |
|---|---|---|
| `native` | **Mach-O and ELF**, per slice: <br>• embedded DWARF (`__DWARF`, `__debug_*`, `.debug_*`, `.zdebug_*`);<br>• the **Mach-O debug map**: stab entries whose `N_OSO` records name every linked object file by absolute build path, plus `N_SO` source files, `N_FUN` functions and `N_AST` Swift modules;<br>• **local symbol names** (defined, non-external `N_SECT`, or ELF `STB_LOCAL` function/object). | DWARF and debug maps forbidden; `maxLocalSymbols: 0`. Fix with `strip -S` / `strip -x` / `strip`. |
| `debugFiles` | Debug artifacts recognised **by content, not name**:<br>• MSF 7.00 / 2.00 PDBs;<br>• portable PDBs;<br>• dSYM companions (Mach-O `MH_DSYM`);<br>• v3 source maps, including indexed `sections` maps and the XSSI `)]}'` prefix. A map with non-empty `sourcesContent` is **critical**, because it ships the original source text. | on |
| `sources` | Original source files by extension: TypeScript (but not `.d.ts`), JSX, Vue, Svelte, CoffeeScript, C/C++/Objective-C, Swift, Rust, Go, Kotlin, Java, C#. | on; skips `node_modules`, `node_modules.asar` and `node_modules.asar.unpacked` |
| `minified` | Owner JavaScript (`include` globs) that is not whitespace-minified, or (at `level: "identifiers"`, the default) whose local identifiers are not mangled. | opt-in |
| `electron` | `webPreferences` object literals that set any of:<br>• `nodeIntegration` / `nodeIntegrationInWorker` / `nodeIntegrationInSubFrames` to `true` or `!0`;<br>• `contextIsolation`, `sandbox` or `webSecurity` to `false` or `!1`;<br>• `allowRunningInsecureContent` or `experimentalFeatures` to true.<br>Keys of nested objects are not attributed. Optionally, `openDevTools()` calls. | opt-in; insecure preferences on, DevTools off |

Each check accepts `exclude` globs. Globs are matched against the release path and the root-relative path; `!/` container separators read as `/`. `native.maxLocalSymbols` sets a per-slice allowance.

`anti-rea inspect` prints these facts (`symbols`, `debug`, `source`, `js`, `electron` lines) with no policy applied.

## 2. Native facts are checked against `dsymutil` and `llvm-objdump`

**Mach-O.** [src/codecs/symbols.ts](../../src/codecs/symbols.ts) walks the load commands (segments, sections, `LC_SYMTAB`) and every `nlist`. The reference is **`dsymutil -s`**, because it prints the raw `nlist` table.

`nm -a` was tried first and is the wrong oracle, for two reasons found during development:

1. It never prints `N_AST` stabs. Ghostty has 49, and they name `.swiftmodule` build paths.
2. On stripped binaries it **invents** names. It shows `<redacted function N>` entries from `LC_FUNCTION_STARTS`, and it shows Objective-C class names from runtime metadata. Neither is in the symbol table. Counting them would report an aid that `strip` cannot remove and that does not exist as a symbol.

**Differential:** 201 Mach-O files (223 slices) from VS Code, ChatGPT, Claude, Figma, Postman, Loom and Ghostty. **Stab and local-symbol counts agree with `dsymutil -s` on 223/223 slices.** 131 of those slices carry a debug map or local symbols.

[test/v07.test.ts](../../test/v07.test.ts) repeats this on up to 60 installed binaries. It also checks clang-built binaries through `strip -S`, `strip -x`, `strip`, `lipo` fat files, and `.o` files with DWARF (against `otool -l`).

**ELF.** The parser reads the section headers (including extended numbering) and `.symtab`. The test cross-compiles with clang for six targets: x86_64, aarch64, i386, armv7, and big-endian powerpc64 and s390x. Each is built with and without `-g`. Debug-section names, `STB_LOCAL` function/object counts and `STT_FILE` names must equal `llvm-objdump -h -t`.

**Limit:** linked ELF images could not be produced here (there is no `ld.lld`), so ELF is validated on relocatable objects only. Windows PE debug directories (CodeView PDB paths) are **not** parsed; shipped `.pdb` files are detected by content.

## 3. The minification classifier

[`jsShape`](../../src/lanes/aids.ts) measures **code only**. A small lexer (`codeOnly`) removes the contents of string, template and regex literals and of comments. It keeps `${…}` expressions and tells regex from division by the previous significant token. Two features are then computed:

| Feature | Measures | Threshold |
|---|---|---|
| `longLineShare` | Share of code bytes on lines over 300 characters | Whitespace-minified if ≥ 0.5 |
| `shortShare` | Share of declared bindings that are 1–2 characters long. Bindings are `var`/`let`/`const`, function names, parameters and `catch`; destructuring keys and exported bindings are excluded. | Mangled if ≥ 0.7, given ≥ 8 bindings |

A file with under 1,024 bytes of code is not judged. Abstentions are counted and reported as limitations, never as passes.

### Round 1: labelled corpus, development and evaluation halves ([bench/minify.mjs](../../bench/minify.mjs))

**Corpus:** 569 real readable files from npm's installed tree. Each also goes through esbuild twice: `minifyWhitespace` + `minifySyntax` (names kept), and full `minify` (names mangled). The halves are split by `sha256(path)`.

**Choosing thresholds:** they were picked from a grid **on the development half only**. 0.7 is the middle of a flat 0.65–0.75 plateau, not the best single cell.

**Evaluation half, scored once:**

| Level | Correct | Accuracy |
|---|---|---|
| Whitespace | 835/840 | **99.4%** |
| Identifiers | 783/789 | **99.2%** |

### Round 2: calibration on nine installed apps

Anti-REA's own `inspect` was run on all nine apps (asar contents included), and every class of flagged file was sampled and labelled by reading it. Three false-positive classes turned up. **Each has a principled fix:**

| Class | Where | Cause | Fix |
|---|---|---|---|
| Embedded text | Claude, ChatGPT | Minified bundles embed Markdown, prompts and component source in literals. Their newlines looked like short code lines, and prose words looked like declarations. | Measure code only (`codeOnly`). Files under 1 KB of code abstain. |
| Destructuring keys | ChatGPT, Claude | In `({size:r=24,…})` the key `size` was counted as a binding, but keys are API names. | Drop destructuring groups. |
| Exports | ChatGPT rspack chunks | `export const __rspack_esm_id…` names are kept by every minifier. | Exclude exported bindings. |

Effect on flagged files:

| App | Before | After |
|---|---|---|
| Claude | 429 | 3 |
| ChatGPT | 2,947 | 55 |
| VS Code | 77 | 1 |
| Postman | 12 | 2 |

**Every remaining flag sampled is true.** Examples:

- VS Code ships `markdown-language-features/dist/serverWorkerMain.js` unminified: 1 MB, 25k lines, tsc output.
- ChatGPT's `orbit-character` runtime ships as readable ES modules; `presentation.mjs` alone is 2,007 lines.
- Postman bundles React DevTools' backend unminified.
- Claude ships a 203-line readable browser shim.

Each fix has a regression test. Each test was **mutation-checked**: reverting the fix in the compiled build makes its test fail. The first version of the export test did *not* fail under mutation, because three exports barely move the ratio of a large file. It was rebuilt to match the small rspack chunk that showed the problem.

### Sealed held-out run (pre-registered, run once)

**Corpus:** a third-party tree no classifier code had seen: `~/Desktop/antibody/node_modules`, a deterministic sample of 600 files. Third-party trees mix readable and pre-minified files, so originals were labelled by an **independent oracle fixed before the run**:

- an original counts as **readable** if esbuild's full minify shrinks it below 60% of its size;
- other originals (already minified, or ambiguous) are dropped;
- variants keep their construction labels.

This ran after the literal-stripping fix and **before** the destructuring and export fixes:

| Level | Correct | Accuracy |
|---|---|---|
| Whitespace | 1,495/1,495 | **100%** |
| Identifiers | 1,399/1,419 | **98.6%** |

11% of samples abstained.

**19 of the 20 identifier errors go the unsafe direction:** whitespace-only output judged mangled. Their original authors already used short names. This is a known limit. Short names are not proof of mangling, and the tool cannot tell a terse author from a mangler.

### Post-hoc rescore after all fixes

Record files:

- [bench/RESULTS-minify-heldout.json](../../bench/RESULTS-minify-heldout.json) is the sealed run.
- [bench/RESULTS-minify-heldout-posthoc.json](../../bench/RESULTS-minify-heldout-posthoc.json) and [bench/RESULTS-minify.json](../../bench/RESULTS-minify.json) are the post-fix rescores.
- The round-1 evaluation figures above come from the run log; that results file was overwritten by the rescore.
- The held-out corpus is a local directory, so that run can be reproduced only on this machine.


These sets have now been seen, so these figures are **not** held-out evidence:

| Set | Whitespace | Identifiers |
|---|---|---|
| npm development | 801/801 | 746/749 |
| npm evaluation | 782/782 | 747/747 |
| antibody held-out | 1,495/1,495 | 1,400/1,419 |

## 4. End to end on installed applications

**Setup:** `anti-rea assure` with `requiredLanes: ["inventory", "aids"]` and the strict defaults. `minified` was enabled for all non-`node_modules` JavaScript, and `electron.forbidDevTools` was on.

**Every one of the nine apps blocks:**

| App | Findings | By check |
|---|---|---|
| VS Code | 763 | 698 debug files (15 maps with sources), 41 native, 13 `.ts` sources, 10 DevTools calls, 1 unminified |
| Postman | 478 | 440 source maps (11 with `sourcesContent`), **18 insecure `webPreferences`**, 9 DevTools calls, 9 native, 2 unminified |
| ChatGPT | 164 | 107 native, **1 shipped `pty.node.dSYM`**, 55 unminified, 1 DevTools call |
| Loom | 29 | native only (vendored Lottie, others) |
| Tailscale | 22 | native only: debug maps in all 22 slices |
| Claude | 21 | 11 native, 7 DevTools calls, 3 unminified |
| Ghostty | 18 | native: main executable has 67k stabs and 36k local symbols, with `/Users/runner/work/…` build paths |
| WhatsApp | 18 | native only |
| Figma | 16 | 10 native, 6 DevTools calls |

Findings confirmed by hand:

- **Postman's main windows** set `webSecurity:!1, nodeIntegration:!0, webviewTag:!0, contextIsolation:!1`. Its other `webPreferences` object (`defaultFontFamily` only) is correctly not flagged.
- **ChatGPT's dSYM** is confirmed by `file` and `dwarfdump --uuid`.
- **Ghostty's debug map** is confirmed by `dsymutil -s`.

**How to read this.** The facts are true. Whether they should block is the owner's call:

- **Much of the native signal is not the team's own code.** It is node-gyp addons under `node_modules`; for VS Code that is 39 of 41 native findings. The rest is vendored frameworks: Sparkle's `Autoupdate` ships with its debug map in Ghostty, Tailscale, WhatsApp and ChatGPT.
- **DevTools calls are often deliberate** (a Help-menu command), and reachability is not analysed.
- Use `exclude`, `maxLocalSymbols` and `forbidDevTools` to state the policy. Record anything temporary as a scoped, expiring exception.

## 5. What this does not do

- **It does not make reverse engineering impossible.** These checks only remove free aids. Exported symbols, Objective-C and Swift runtime metadata, string literals and the program's behaviour always ship.
- **No transformations.** It does not obfuscate, pack, encrypt or add anti-debugging. Those are research stage 5, out of scope until measurements justify them.
- **No reachability analysis.** `openDevTools()` is reported wherever it appears. `webPreferences` are read only from object literals, not from values computed at runtime.
- **No PE semantics** beyond detecting PDB content.

## 6. Tests

[test/v07.test.ts](../../test/v07.test.ts) has 12 tests:

- **Mach-O (3)**, against `dsymutil` and `otool` on clang-built and installed binaries;
- **ELF (1)**, against `llvm-objdump` on six targets;
- **content detection of debug files (1)**;
- **the lexer (1)**;
- **minification levels on real esbuild output (1)**;
- **three mutation-checked calibration regressions (1)**;
- **Electron leads (1)**;
- **manifest validation (1)**;
- **two `assure()` end-to-end tests:**
  - a vulnerable Electron release blocks on every aid, and its fixed build passes;
  - a native release blocks until `strip`, and honours exclusions and thresholds.

Tests that need `clang`, `dsymutil` or `llvm-objdump` are skipped where those tools are missing. The suite ran 5 times in a row with identical results. The full suite is 108/108.
