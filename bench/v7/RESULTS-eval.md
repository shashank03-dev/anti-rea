# v7 results: the exposure report on real toolchain builds

**Run once, on 2026-11-07, against the frozen tree `dfc1343a…`, pre-registered in commit `a8d681b`
([PREREGISTRATION.md](PREREGISTRATION.md)).** 240 cases, 0 excluded, 0 tool errors.

## Summary

| | Anti-REA (`expose`) | Checklist baseline |
|---|---|---|
| Accuracy, as registered (624 units) | **97.0%** [95.3, 98.2] | 96.3% [94.5, 97.6] |
| Accuracy, post-hoc correction (566 units, see below) | **96.6%** [94.8, 98.0] | 95.9% [94.0, 97.4] |
| False positives on hardened builds | **0 of 333** (95% CI upper bound 1.1%) | 0 of 333 |
| Native: Go ELF/PE/Mach-O executables and C dylibs, vs the reference | **100%** (278/278) | 100% |
| Source maps (external and inline), detected / severity right | **66/66** / **66/66** | 66/66 / — |
| `openDevTools()` calls | **43/43** | 43/43 |
| Insecure `webPreferences`, literal values | **34/34** | 20/34 |
| Insecure `webPreferences` passed through a variable | **0/19** (predicted miss, P1) | 10/19 |

95% intervals are exact (Clopper–Pearson).

**What this supports:**
- On real builds of real code, `anti-rea expose` reported every debug-info, symbol-table, debug-map, dSYM,
  source-map and DevTools exposure the reference found, across ELF, PE and Mach-O, and inside zip, tar.gz and
  app.asar packaging.
- It raised no false alarm on any hardened build.
- Every one of its errors is a single, documented scope gap: a `webPreferences` value passed through a variable
  instead of written in the object literal. It was predicted before the run.

**What this does not support:** that Anti-REA is more accurate than a careful engineer's checklist (H3; exact
McNemar p = 0.54). That was predicted too (P4). Anti-REA is as accurate as a ~100-line expert script that runs
llvm-objdump, llvm-nm, unzip, tar, asar and regexes over every file. Anti-REA does it in one command, attributes
each finding to owner or third-party code, grades it, and names the fix. The baseline caught 10 of the 19
variable-passed values, because its regex matched their declarations. Anti-REA caught all 14 minified ones
(`!0`/`!1`), which the baseline cannot see.

## Hypotheses (as registered, evaluated mechanically)

| | Claim | Result |
|---|---|---|
| H1 | Accuracy ≥ 95% and 95% CI lower bound ≥ 93% | **supported** (97.0%, lower bound 95.3%; post-hoc 96.6%, lower bound 94.8%) |
| H2 | False-positive rate ≤ 2% | **supported** (0%) |
| H3 | More accurate than the baseline, McNemar p < 0.01 | **not supported** (p = 0.54) |
| H4 | Native units agree with the reference on ≥ 99% | **supported** (100%) |
| H5 | Every class: recall ≥ 90% (P1 excluded) and specificity ≥ 95% | **supported** |

## Predictions, scored

| | Prediction | Outcome |
|---|---|---|
| P1 | Indirect `webPreferences`: AR recall ≤ 20%; BL catches the non-minified ones | **held.** AR 0/19; BL 10/19 |
| P2 | Minified literal values: AR ≥ 95%, BL 0% | **held.** AR 14/14, BL 0/14 |
| P3 | Native: AR and BL ≥ 99% vs the reference | **held.** Both 100% |
| P4 | H3 not supported | **held.** p = 0.54 |
| P5 | No AR false positive from documentation text | **held.** 0 of 21 hard-negative units |
| P6 | Severity grade matches `sourcesContent` on ≥ 99% | **held.** 66/66 |

## A harness defect, found after the run (disclosed, with a post-hoc correction)

**29 of the 96 Go cases built a Go package archive, not an executable.** Subject discovery (§4) accepted
directories whose only `package main` file is a `//go:build ignore` code generator inside a library (mostly
`golang.org/x/text`). `go build -o` then writes a package archive (`!<arch>`). Both systems are trivially right
on such an artifact, so those 58 units inflate both scores. The dev set had the same flaw and it was not caught
there.

The registered protocol forbids a second eval run. The registered numbers are therefore reported unchanged
above, and [posthoc.mjs](posthoc.mjs) recomputes them without those 29 cases, labelled post-hoc everywhere:
[RESULTS-eval.posthoc.json](RESULTS-eval.posthoc.json). No conclusion changes. 67 real Go executables remain
(22 ELF, 20 PE, 25 Mach-O), and both systems stay at 100% on them. The next study's discovery must require that
the built artifact is an executable.

## Construction vs reference

The toolchain did not always do what its flags suggest. Truth followed the reference, as registered (§3.1):
- `strip -x` on a Mach-O dylib also removes the debug map;
- QuickJS compiled at `-O1` keeps no local symbols;
- the 29 package archives above.

All cases are listed in the registered output below.

## Reproduce

```bash
git checkout a8d681b
node bench/v7/subjects.mjs     # optional: rediscover subjects (needs the same caches)
node bench/v7/corpus.mjs --set eval
node bench/v7/run.mjs --set eval
node bench/v7/score.mjs --set eval
```

The run refuses any tree whose hash differs from the pre-registered one. **The released 0.1.0 has the same `src/` as
the frozen tree, byte for byte.** Only `package.json` metadata (repository, keywords, packed files) changed after
the run, so these results describe the shipped analyzers. Raw per-case truth and decisions are in
[eval-data/](eval-data/), so the numbers can be recomputed without rebuilding anything.

**Scope.** v7 covers Go (ELF/PE/Mach-O), C (Mach-O) and JS/Electron. The APK, .NET, Unity, PyInstaller, WASM,
ML-model, Godot and GPU analyzers were not evaluated. The C cases come from two libraries and are clustered. See
PREREGISTRATION.md §9.

---

# Registered output (verbatim from `score.mjs`)


Frozen tree: `dfc1343aee1e4f1a0acfd216adc97af85fadd198f401291b996920d80f601842`. Cases: 240 generated, 0 excluded (build failures, §5.4), 0 tool errors (scored wrong). Units (case × class): **624**.

| | Accuracy | 95% CI | False-positive rate |
|---|---|---|---|
| **AR** (anti-rea expose) | **97.0%** (605/624) | [95.3, 98.2] | 0.0% (0/391) |
| BL (checklist baseline) | 96.3% (601/624) | [94.5, 97.6] | 0.0% (0/391) |

McNemar (exact, two-sided): AR right/BL wrong = 14, AR wrong/BL right = 10, p = 0.541.

## Hypotheses (evaluated mechanically)

| | Claim | Result |
|---|---|---|
| H1 | AR overall accuracy ≥ 95% and exact 95% CI lower bound ≥ 93% | **supported** |
| H2 | AR false-positive rate on truth-negative units ≤ 2% | **supported** |
| H3 | AR accuracy > BL accuracy, exact McNemar p < 0.01 | **not supported** |
| H4 | On native units (Go + C), AR agrees with the reference on ≥ 99% | **supported** |
| H5 | Every class: AR recall ≥ 90% (indirect webPreferences excluded, P1) and specificity ≥ 95% | **supported** |

## Per class

| Class | Units | AR recall | AR specificity | BL recall | BL specificity |
|---|---|---|---|---|---|
| dwarf | 96 | 100.0% (13/13) | 100.0% (83/83) | 100.0% | 100.0% |
| locals | 144 | 100.0% (40/40) | 100.0% (104/104) | 100.0% | 100.0% |
| debugmap | 48 | 100.0% (10/10) | 100.0% (38/38) | 100.0% | 100.0% |
| dsym | 48 | 100.0% (8/8) | 100.0% (40/40) | 100.0% | 100.0% |
| map | 96 | 100.0% (66/66) | 100.0% (30/30) | 100.0% | 100.0% |
| webprefs | 96 | 64.2% (34/53) | 100.0% (43/43) | 56.6% | 100.0% |
| devtools | 96 | 100.0% (43/43) | 100.0% (53/53) | 100.0% | 100.0% |

## Strata

| Stratum | Units | AR | BL |
|---|---|---|---|
| family=go | 192 | 100.0% | 100.0% |
| family=c | 144 | 100.0% | 100.0% |
| family=js | 288 | 93.4% | 92.0% |
| go format=elf | 58 | 100.0% | 100.0% |
| go format=pe | 56 | 100.0% | 100.0% |
| go format=macho | 78 | 100.0% | 100.0% |
| packaging=direct | 83 | 100.0% | 100.0% |
| packaging=zip | 132 | 100.0% | 100.0% |
| packaging=tgz | 121 | 100.0% | 100.0% |
| packaging=dir | 105 | 96.2% | 91.4% |
| packaging=asar | 108 | 89.8% | 91.7% |
| packaging=asar-in-zip | 75 | 94.7% | 93.3% |
| webprefs insecure, literal, not minified | 20 | 100.0% | 100.0% |
| webprefs insecure, literal, minified (!0/!1) | 14 | 100.0% | 0.0% |
| webprefs insecure, indirect (P1: out of scope) | 19 | 0.0% | 52.6% |
| hard-negative mentions (webprefs+devtools negatives) | 21 | 100.0% | 100.0% |
| map=reference-only (comment, map not shipped) | 13 | 100.0% | 100.0% |
| map=external-sources | 15 | 100.0% | 100.0% |
| map=external-names | 13 | 100.0% | 100.0% |
| map=inline-sources | 22 | 100.0% | 100.0% |
| map=inline-names | 16 | 100.0% | 100.0% |
| map=none | 17 | 100.0% | 100.0% |

Secondary (§6.4): on shipped maps AR detected, its grade matched whether `sourcesContent` ships on 66/66.

## Construction vs reference

38 case(s) where the toolchain did not do what its flags suggest; truth follows the reference (§3.1):

- 020 go:golang.org/x/net@v0.54.0/html/atom {"goos":"windows","goarch":"amd64","ldflags":"","trimpath":false,"packaging":"zip"}: construction {"dwarf":true,"locals":true} vs reference {"dwarf":false,"locals":false}
- 023 go:golang.org/x/text@v0.37.0/encoding/traditionalchinese {"goos":"darwin","goarch":"arm64","ldflags":"","trimpath":true,"packaging":"direct"}: construction {"dwarf":true,"locals":true} vs reference {"dwarf":false,"locals":false}
- 027 go:golang.org/x/text@v0.37.0/unicode/cldr {"goos":"darwin","goarch":"arm64","ldflags":"","trimpath":true,"packaging":"tgz"}: construction {"dwarf":true,"locals":true} vs reference {"dwarf":false,"locals":false}
- 032 go:golang.org/x/text@v0.37.0/encoding/charmap {"goos":"darwin","goarch":"arm64","ldflags":"","trimpath":false,"packaging":"tgz"}: construction {"dwarf":true,"locals":true} vs reference {"dwarf":false,"locals":false}
- 033 go:golang.org/x/text@v0.37.0/feature/plural {"goos":"linux","goarch":"amd64","ldflags":"","trimpath":false,"packaging":"direct"}: construction {"dwarf":true,"locals":true} vs reference {"dwarf":false,"locals":false}
- 035 go:golang.org/x/text@v0.37.0/language {"goos":"darwin","goarch":"arm64","ldflags":"-w","trimpath":false,"packaging":"zip"}: construction {"dwarf":false,"locals":true} vs reference {"dwarf":false,"locals":false}
- 048 go:modernc.org/libc@v1.74.1 {"goos":"windows","goarch":"amd64","ldflags":"-w","trimpath":true,"packaging":"tgz"}: construction {"dwarf":false,"locals":true} vs reference {"dwarf":false,"locals":false}
- 056 go:golang.org/x/text@v0.37.0/encoding/ianaindex {"goos":"darwin","goarch":"arm64","ldflags":"","trimpath":true,"packaging":"zip"}: construction {"dwarf":true,"locals":true} vs reference {"dwarf":false,"locals":false}
- 058 go:golang.org/x/text@v0.37.0 {"goos":"darwin","goarch":"arm64","ldflags":"-w","trimpath":true,"packaging":"tgz"}: construction {"dwarf":false,"locals":true} vs reference {"dwarf":false,"locals":false}
- 059 go:golang.org/x/text@v0.37.0/encoding/japanese {"goos":"darwin","goarch":"arm64","ldflags":"","trimpath":true,"packaging":"direct"}: construction {"dwarf":true,"locals":true} vs reference {"dwarf":false,"locals":false}
- 068 go:golang.org/x/text@v0.37.0/unicode/rangetable {"goos":"windows","goarch":"amd64","ldflags":"-w","trimpath":true,"packaging":"zip"}: construction {"dwarf":false,"locals":true} vs reference {"dwarf":false,"locals":false}
- 078 go:modernc.org/sqlite@v1.55.0 {"goos":"darwin","goarch":"arm64","ldflags":"-w","trimpath":false,"packaging":"direct"}: construction {"dwarf":false,"locals":true} vs reference {"dwarf":false,"locals":false}
- 082 go:golang.org/x/text@v0.37.0/unicode/rangetable {"goos":"darwin","goarch":"arm64","ldflags":"","trimpath":true,"packaging":"direct"}: construction {"dwarf":true,"locals":true} vs reference {"dwarf":false,"locals":false}
- 085 go:golang.org/x/text@v0.37.0/secure/precis {"goos":"linux","goarch":"amd64","ldflags":"","trimpath":false,"packaging":"tgz"}: construction {"dwarf":true,"locals":true} vs reference {"dwarf":false,"locals":false}
- 089 go:golang.org/x/sys@v0.44.0/unix {"goos":"darwin","goarch":"arm64","ldflags":"","trimpath":true,"packaging":"tgz"}: construction {"dwarf":true,"locals":true} vs reference {"dwarf":false,"locals":false}
- 093 go:golang.org/x/text@v0.37.0/date {"goos":"darwin","goarch":"arm64","ldflags":"-w","trimpath":true,"packaging":"tgz"}: construction {"dwarf":false,"locals":true} vs reference {"dwarf":false,"locals":false}
- 097 c:quickjs {"g":false,"strip":"-S","shipDsym":false,"packaging":"zip","units":2}: construction {"debugmap":false,"locals":true,"dsym":false} vs reference {"debugmap":false,"locals":false,"dsym":false}
- 098 c:zstd {"g":true,"strip":"-x","shipDsym":false,"packaging":"zip","units":39}: construction {"debugmap":true,"locals":false,"dsym":false} vs reference {"debugmap":false,"locals":false,"dsym":false}
- 101 c:quickjs {"g":false,"strip":"none","shipDsym":false,"packaging":"zip","units":2}: construction {"debugmap":false,"locals":true,"dsym":false} vs reference {"debugmap":false,"locals":false,"dsym":false}
- 102 c:zstd {"g":true,"strip":"-x","shipDsym":false,"packaging":"tgz","units":39}: construction {"debugmap":true,"locals":false,"dsym":false} vs reference {"debugmap":false,"locals":false,"dsym":false}
- 103 c:quickjs {"g":true,"strip":"-S","shipDsym":true,"packaging":"zip","units":2}: construction {"debugmap":false,"locals":true,"dsym":true} vs reference {"debugmap":false,"locals":false,"dsym":true}
- 105 c:quickjs {"g":false,"strip":"none","shipDsym":false,"packaging":"tgz","units":2}: construction {"debugmap":false,"locals":true,"dsym":false} vs reference {"debugmap":false,"locals":false,"dsym":false}
- 106 c:quickjs {"g":true,"strip":"none","shipDsym":false,"packaging":"direct","units":2}: construction {"debugmap":true,"locals":true,"dsym":false} vs reference {"debugmap":true,"locals":false,"dsym":false}
- 108 c:quickjs {"g":false,"strip":"none","shipDsym":false,"packaging":"tgz","units":2}: construction {"debugmap":false,"locals":true,"dsym":false} vs reference {"debugmap":false,"locals":false,"dsym":false}
- 109 c:zstd {"g":true,"strip":"-x","shipDsym":true,"packaging":"tgz","units":39}: construction {"debugmap":true,"locals":false,"dsym":true} vs reference {"debugmap":false,"locals":false,"dsym":true}
- 112 c:zstd {"g":true,"strip":"-x","shipDsym":false,"packaging":"direct","units":39}: construction {"debugmap":true,"locals":false,"dsym":false} vs reference {"debugmap":false,"locals":false,"dsym":false}
- 113 c:quickjs {"g":true,"strip":"-x","shipDsym":false,"packaging":"zip","units":2}: construction {"debugmap":true,"locals":false,"dsym":false} vs reference {"debugmap":false,"locals":false,"dsym":false}
- 115 c:quickjs {"g":false,"strip":"-S","shipDsym":false,"packaging":"zip","units":2}: construction {"debugmap":false,"locals":true,"dsym":false} vs reference {"debugmap":false,"locals":false,"dsym":false}
- 117 c:quickjs {"g":true,"strip":"none","shipDsym":false,"packaging":"zip","units":2}: construction {"debugmap":true,"locals":true,"dsym":false} vs reference {"debugmap":true,"locals":false,"dsym":false}
- 120 c:quickjs {"g":true,"strip":"-S","shipDsym":true,"packaging":"zip","units":2}: construction {"debugmap":false,"locals":true,"dsym":true} vs reference {"debugmap":false,"locals":false,"dsym":true}

## Every AR error

- 155 js/js **webprefs** truth=true AR=false {"map":"inline-sources","minify":false,"insecure":"contextIsolation: false","style":"indirect","devtools":false,"hardNegative":false,"packaging":"asar"}
- 156 js/js **webprefs** truth=true AR=false {"map":"inline-sources","minify":true,"insecure":"nodeIntegration: true","style":"indirect","devtools":true,"hardNegative":true,"packaging":"asar"}
- 169 js/js **webprefs** truth=true AR=false {"map":"external-sources","minify":true,"insecure":"nodeIntegration: true","style":"indirect","devtools":true,"hardNegative":false,"packaging":"dir"}
- 173 js/js **webprefs** truth=true AR=false {"map":"none","minify":true,"insecure":"contextIsolation: false","style":"indirect","devtools":true,"hardNegative":false,"packaging":"asar-in-zip"}
- 176 js/js **webprefs** truth=true AR=false {"map":"inline-sources","minify":false,"insecure":"allowRunningInsecureContent: true","style":"indirect","devtools":true,"hardNegative":true,"packaging":"asar"}
- 203 js/js **webprefs** truth=true AR=false {"map":"inline-sources","minify":false,"insecure":"sandbox: false","style":"indirect","devtools":true,"hardNegative":true,"packaging":"dir"}
- 205 js/js **webprefs** truth=true AR=false {"map":"reference-only","minify":false,"insecure":"contextIsolation: false","style":"indirect","devtools":false,"hardNegative":false,"packaging":"asar"}
- 208 js/js **webprefs** truth=true AR=false {"map":"inline-names","minify":false,"insecure":"nodeIntegration: true","style":"indirect","devtools":false,"hardNegative":false,"packaging":"asar"}
- 212 js/js **webprefs** truth=true AR=false {"map":"external-sources","minify":false,"insecure":"contextIsolation: false","style":"indirect","devtools":false,"hardNegative":false,"packaging":"asar"}
- 214 js/js **webprefs** truth=true AR=false {"map":"none","minify":false,"insecure":"contextIsolation: false","style":"indirect","devtools":false,"hardNegative":false,"packaging":"dir"}
- 215 js/js **webprefs** truth=true AR=false {"map":"none","minify":true,"insecure":"allowRunningInsecureContent: true","style":"indirect","devtools":true,"hardNegative":false,"packaging":"asar"}
- 216 js/js **webprefs** truth=true AR=false {"map":"none","minify":true,"insecure":"nodeIntegration: true","style":"indirect","devtools":false,"hardNegative":true,"packaging":"dir"}
- 218 js/js **webprefs** truth=true AR=false {"map":"inline-sources","minify":true,"insecure":"allowRunningInsecureContent: true","style":"indirect","devtools":true,"hardNegative":false,"packaging":"asar"}
- 219 js/js **webprefs** truth=true AR=false {"map":"external-sources","minify":true,"insecure":"webSecurity: false","style":"indirect","devtools":false,"hardNegative":false,"packaging":"asar"}
- 222 js/js **webprefs** truth=true AR=false {"map":"inline-sources","minify":false,"insecure":"contextIsolation: false","style":"indirect","devtools":true,"hardNegative":false,"packaging":"asar-in-zip"}
- 228 js/js **webprefs** truth=true AR=false {"map":"external-sources","minify":false,"insecure":"nodeIntegration: true","style":"indirect","devtools":false,"hardNegative":true,"packaging":"asar-in-zip"}
- 231 js/js **webprefs** truth=true AR=false {"map":"reference-only","minify":false,"insecure":"webSecurity: false","style":"indirect","devtools":true,"hardNegative":false,"packaging":"asar"}
- 234 js/js **webprefs** truth=true AR=false {"map":"none","minify":true,"insecure":"contextIsolation: false","style":"indirect","devtools":false,"hardNegative":false,"packaging":"asar"}
- 238 js/js **webprefs** truth=true AR=false {"map":"external-sources","minify":true,"insecure":"contextIsolation: false","style":"indirect","devtools":true,"hardNegative":false,"packaging":"asar-in-zip"}
