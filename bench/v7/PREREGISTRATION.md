# Pre-registration v7: the exposure report (`anti-rea expose`) on real toolchain builds

**Registered:** 2026-11-07, before the eval corpus was generated. No tool has been run on any eval case. This file
is committed before the eval run; the commit's timestamp and the frozen hash below are the evidence of order.

**Frozen tool and harness:** frozen-sha256: `dfc1343aee1e4f1a0acfd216adc97af85fadd198f401291b996920d80f601842`

`node bench/v7/freeze.mjs` computes it over `src/`, `package.json`, `bench/v7/{freeze,subjects,corpus,baseline,run,score}.mjs`,
`bench/v7/subjects.json` and `bench/v7/refcheck/{main.go,go.mod}`. **Eval seed:** the first 32 bits of that hash.
`bench/v7/run.mjs --set eval` refuses to run on any other tree or seed.

Earlier studies (v1–v6, in `bench/`) measured the **release gate** (`assure`: leaked secrets, server-only code).
v7 is the first study of the **exposure report** (`expose`), the feature that tells a developer what a
reverse-engineering tool would recover from their build.

## 1. Questions

1. **Accuracy.** On real builds of real third-party code, with known toolchain settings, does `anti-rea expose`
   report each avoidable reverse-engineering aid exactly when it ships?
2. **False alarms.** On hardened builds, does it stay quiet?
3. **Comparison.** Is it more accurate than a careful release engineer's checklist built from standard tools?

## 2. Systems

### 2.1 AR — Anti-REA

`anti-rea expose <case>/release --json --include-third-party`, built from the frozen tree (version 0.1.0). AR's
decision for a class is whether any finding of that class appears (§3.2).

### 2.2 BL — the checklist baseline

`bench/v7/baseline.mjs`: what a careful release engineer would script with tools they already have. It **expands
archives first** (unzip, tar, `@electron/asar extract`, up to 4 levels), so packaging alone cannot make it lose:

| Class | BL rule |
|---|---|
| dwarf | `objdump -h` (llvm-objdump) lists a section `.debug_*` / `.zdebug_*` / `__debug_*` / `__zdebug_*` |
| locals | `nm` (llvm-nm) prints a defined symbol with a lowercase type letter `t d b s r` |
| debugmap | `nm -a` prints an `OSO` or `SO` stab whose name is not a directory |
| dsym | a directory named `*.dSYM` exists |
| map | a `*.map` file exists, or a script contains `sourceMappingURL=data:` |
| webprefs | a script matches `nodeIntegration*: true`, `contextIsolation: false`, `sandbox: false`, `webSecurity: false` or `allowRunningInsecureContent: true` (whitespace-tolerant) |
| devtools | a script matches `openDevTools(` |

Binary checks skip files inside `*.dSYM` bundles.

## 3. Truth and classes

### 3.1 Truth

- **Native (Go, C):** `bench/v7/refcheck`, an implementation independent of Anti-REA's TypeScript parsers, built
  on Go's standard library (`debug/elf`, `debug/pe`, `debug/macho`), run on the built bytes before packaging.
  The construction expectation (what the flags should produce) is recorded beside it. **Where they disagree, the
  reference is the truth**, and every disagreement is listed in the results.
- **JavaScript:** construction. The harness plants every value, so it knows them exactly.

### 3.2 Classes, definitions and AR finding titles

| Class | Definition (reference) | AR finding title(s) |
|---|---|---|
| dwarf | a `.debug_*`/`.zdebug_*` section (ELF, PE) or `__debug_*`/`__zdebug_*`/segment `__DWARF` (Mach-O) | Embedded DWARF debug information |
| locals | ELF: defined, named `STB_LOCAL` FUNC/OBJECT; Mach-O: named non-stab non-external `N_SECT` except `__mh_*_header`; PE: a COFF symbol table with ≥ 1 entry | Unstripped local symbol names · Unstripped .symtab with local symbols · COFF symbol table shipped |
| debugmap | Mach-O stabs naming an object (`N_OSO`) or source file (`N_SO`, not a directory) | Debug map (stabs): … |
| dsym | a shipped Mach-O `MH_DSYM` file | dSYM debug companion shipped |
| map | a source map ships (external file or inline `data:` URL) | (Inline) source map ships the original source · (Inline) source map restores original names and layout |
| webprefs | an insecure value in the `webPreferences` object of a `BrowserWindow` | Insecure Electron webPreferences: … |
| devtools | an `openDevTools()` call in shipped code | Electron DevTools opened from shipped code |

**Applicability:** Go: dwarf, locals. C (Mach-O dylib): debugmap, locals, dsym. JS: map, webprefs, devtools.

## 4. Subjects

`bench/v7/subjects.json`, discovered once by `bench/v7/subjects.mjs` from code on the registering machine that no
earlier calibration or benchmark used. Only subjects that **build offline** are kept, so the corpus reproduces
from the recorded pool.

| Pool | Source | Dev | Eval |
|---|---|---|---|
| go | `package main` directories in the Go module cache that build with `GOPROXY=off` | 34 | 72 |
| c | C libraries vendored in Rust crates (dev: SQLite, FreeType, aws-lc; eval: zstd, QuickJS) | 3 | 2 |
| js | packages in the Homebrew npm install that esbuild bundles for node | 19 | 86 |

**Split rule (fixed before discovery):** `sha256(subject id)[0] < 64` → dev, else eval. Dev and eval subjects are
disjoint.

## 5. Corpus

`bench/v7/corpus.mjs`. Sizes: **eval 240 cases** (go 96, c 48, js 96); dev 40 (16, 8, 16). Every factor below is drawn
from a seeded PRNG (mulberry32).

- **go:** GOOS/GOARCH ∈ {linux/amd64 (ELF), windows/amd64 (PE), darwin/arm64 (Mach-O)}, `-ldflags` ∈ {none, `-w`,
  `-s -w`, `-s`}, `-trimpath` ∈ {no, yes}, packaging ∈ {direct, zip, tar.gz}.
- **c:** a dylib linked from the library's translation units: `-g` (p = 0.6), strip ∈ {none, `-S`, `-x`, `-S -x`},
  dSYM shipped (p = 0.5 when `-g`), packaging ∈ {direct, zip, tar.gz}.
- **js:** an Electron main bundle (esbuild) of a real package plus a `BrowserWindow`:
  - map ∈ {none, external with sources, external names only, inline with sources, inline names only,
    reference-only (comment present, map not shipped)};
  - minify (p = 0.5);
  - one insecure `webPreferences` value (p = 0.5; uniformly from nodeIntegration: true, contextIsolation: false,
    sandbox: false, webSecurity: false, allowRunningInsecureContent: true), else all secure;
  - style literal, or **indirect** (p = 0.25: values passed through a variable);
  - `openDevTools()` (p = 0.4);
  - hard-negative documentation text naming the same settings and call (p = 0.25);
  - packaging ∈ {dir, app.asar, app.asar inside a zip}.

**§5.4 Build failures:** a case whose build fails is recorded and **excluded**. It is listed, never scored as a pass.

## 6. Scoring

- **§6.1 Unit:** one (case, applicable class) decision against the truth.
- **§6.2 Statistics:** exact Clopper–Pearson 95% intervals; exact two-sided McNemar test on paired units.
- **§6.3 Tool errors:** a case where AR exits non-zero counts as **wrong for every class** of that case.
- **§6.4 Secondary:** on shipped maps AR detects, whether its grade (critical with sources, high without) matches
  whether `sourcesContent` ships.

## 7. Hypotheses and predictions

| | Hypothesis |
|---|---|
| H1 | AR overall accuracy ≥ 95%, and its exact 95% CI lower bound ≥ 93% |
| H2 | AR false-positive rate on truth-negative units ≤ 2% |
| H3 | AR accuracy > BL accuracy, exact McNemar p < 0.01 |
| H4 | On native units (Go + C), AR agrees with the reference on ≥ 99% |
| H5 | Every class: AR recall ≥ 90% (indirect `webPreferences` excluded, P1) and specificity ≥ 95% |

Predictions, written before the eval run:

- **P1.** Indirect `webPreferences` (value passed through a variable) is outside AR's documented scope (literal
  `webPreferences` objects): AR recall ≤ 20% there. BL's regex matches the variable's declaration, so BL catches
  these when the bundle is not minified.
- **P2.** Minified literal values (`!0`/`!1`): AR recall ≥ 95%; BL 0% (its regex matches only `true`/`false`).
- **P3.** Native: AR and BL both agree with the reference on ≥ 99% of units.
- **P4.** **H3 is predicted not supported.** Dev showed BL is strong; the discordant units are few and split between
  P2 (AR wins) and P1 (BL wins).
- **P5.** Hard-negative documentation text produces no false positive for AR (dev: 0 of 7 units).
- **P6.** The §6.4 grade matches on ≥ 99% of shipped maps AR detects.

## 8. Dev-set disclosure (a deviation from the v1–v6 protocol)

In v1–v6, dev results never led to a change in `src/`. **v7 departs from that, and says so.** Before any eval case
existed, the dev set exposed two head-only prefilters in the exposure analyzers. They are real customer-facing
misses, so they were fixed rather than carried into a shipped product:

1. `debug-files`: the source-map prefilter read only the first 1 MiB. esbuild and webpack write `sourcesContent`
   before `mappings`, so a 3.5 MB map shipping the full original source produced no finding.
2. `js-electron`: Electron detection read only the first 1 MiB. Bundlers put the entry module (the code that builds
   the `BrowserWindow`) last, so Electron main bundles over 1 MiB were never analyzed.

Dev is therefore **tuning data**. The eval pool is disjoint (§4) and was not built until after registration. Two
further gaps were found by code review before the dev run, and fixed: DWARF and COFF symbols in PE images, and
inline (`data:`) source maps in `expose`.

Dev after the fixes: AR 99.0% (103/104), BL 98.1% (102/104), 0 false positives for either. The single AR error is a
P1 case.

## 9. Threats to validity

- **Narrow scope.** v7 measures three families: Go (ELF/PE/Mach-O), C (Mach-O dylibs) and JS/Electron. The APK,
  .NET, Unity, PyInstaller, WASM, ML-model, Godot and GPU analyzers are **not** evaluated here.
- **Clustered C cases.** The eval C cases come from two libraries (zstd, QuickJS), so they are not independent.
- **Truth by shared definition.** For native classes the reference implements the same definitions Anti-REA
  documents. v7 tests that the bytes are read correctly, across formats and containers, not whether the definitions
  are the right ones.
- **JS truth is construction.** The planted `BrowserWindow` code is the harness's, not the subject's.
- **One machine, one toolchain:** Go 1.27.2, Apple clang 21, esbuild 0.28 (recorded in `subjects.json`).
- **The author wrote the baseline.** BL's rules are fixed above; a different engineer might script them differently.

## 10. Procedure

```bash
node bench/v7/corpus.mjs --set eval
node bench/v7/run.mjs --set eval
node bench/v7/score.mjs --set eval
```

The eval run happens once. Its results are copied to `bench/v7/RESULTS-eval.md` and `bench/v7/RESULTS-eval.summary.json`,
reported in full, losses included.
