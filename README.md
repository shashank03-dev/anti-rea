<div align="center">

# Anti-REA

**Find out what a reverse engineer would get from your build — before you ship it.**

[![npm](https://img.shields.io/npm/v/@anti-rea/cli?color=cb3837&label=npm)](https://www.npmjs.com/package/@anti-rea/cli)
[![CI](https://github.com/shashank03-dev/anti-rea/actions/workflows/ci.yml/badge.svg)](https://github.com/shashank03-dev/anti-rea/actions/workflows/ci.yml)
![node](https://img.shields.io/badge/node-%E2%89%A5%2022-339933)
![dependencies](https://img.shields.io/badge/runtime%20deps-0-blue)
[![license](https://img.shields.io/badge/license-proprietary-lightgrey)](LICENSE)

[Quick start](#quick-start) · [What you get](#what-you-get) · [Use it with your AI agent](#use-it-with-your-ai-agent) · [Evidence](#evidence) · [Reference](docs/REFERENCE.md)

</div>

---

Debug symbols, source maps, original source files, DevTools left on, a server-only secret bundled by mistake. Release builds leak these all the time, and reverse-engineering tools recover them in seconds.

Anti-REA reads the bytes you are about to ship, including what's inside `app.asar`, zip/apk/ipa, tar, DMG and nested archives. It then does two things:

| | Command | What it does |
|---|---|---|
| 🔍 | **`expose`** | An advisory report: *what would a reverse-engineering tool recover, is it your code or a dependency's, and which build setting removes it.* No setup needed. |
| 🚦 | **`assure`** | A release gate: **ship or block**, decided by hard rules against what you declared must never ship. Optionally signs the decision. |

It is static and read-only. It makes no network calls, needs no runtime dependencies, and never prints a secret it finds.

## Quick start

```bash
npm install --save-dev @anti-rea/cli
```

**1. See your exposure.** Point it at what your build produces: a `.app`, `.apk`, `.ipa`, `.exe`, or a folder.

```bash
npx anti-rea expose dist/MyApp.app
```

**2. Fix, re-run, repeat.** Every finding names the setting that removes it, such as `strip -S`, `-ldflags="-s -w"`, R8, or building without `sourcesContent`.

**3. Gate the release.** Scaffold a manifest and policy from your build, declare what must never ship, then run the gate:

```bash
npx anti-rea init dist
```

```bash
npx anti-rea fingerprint --file path/to/server-only-secret.pem
```

```bash
npx anti-rea assure --manifest anti-rea.manifest.json --policy anti-rea.policy.json --out anti-rea-report
```

`assure` exits **0** to ship and **2** to block. It keeps blocking until you have declared at least one asset: a release can't pass before its owner has said what must not ship.

## What you get

```text
$ npx anti-rea expose release
highest exposure: CRITICAL (owner code: CRITICAL); 30 owner, 1 third-party finding(s)
  [critical] Source map ships the original source — release/resources/app.asar!/renderer/app.js.map
  [critical] Original source file shipped — release/src/app.ts
  [high] android:debuggable="true" — release/mobile/app.apk!/AndroidManifest.xml
  [high] Embedded DWARF debug information — release/native/app-linux
  [high] Insecure Electron webPreferences: nodeIntegration: true — release/resources/app.asar!/preload.js
  … 20 more owner finding(s) in the report
checklist: 28 action(s)
```

<sub>Output from the bundled synthetic demo (`npm run expose-demo`), shortened.</sub>

Each finding in `exposure.md` / `exposure.json` comes with:

- **Recovers:** what an attacker gets, for example *"the original, unminified source text, inlined in the map's sourcesContent"*.
- **Fix:** the exact change, for example *"do not ship .map files; upload them to your error-tracking service, or build without sourcesContent"*.
- **Owner vs third-party**, so your own code ranks first.
- **Avoidable vs inherent**, so you know what a setting can fix and what is built into the platform (Go `pclntab`, IL2CPP metadata).
- A severity from a **fixed rubric**. `--fail-on` uses the worst grade, never an average.

**Formats covered:** Mach-O, ELF and PE · Electron · .NET · Unity IL2CPP · Android APK · Flutter · Go · Rust · PyInstaller · WebAssembly · ML models (GGUF, safetensors, TFLite) · Godot · GPU kernels. The detail, including what is only detected rather than fully analyzed, is in [REA-COVERAGE.md](docs/REA-COVERAGE.md).

## Use it with your AI agent

Register the read-only MCP server once:

```bash
claude mcp add anti-rea -- npx -y -p @anti-rea/cli anti-rea-mcp
```

Then ask:

> *"Run expose_release on dist/ and fix every avoidable owner finding in our build config."*

The agent reads the report, edits your build settings, and re-runs until the avoidable findings are gone. [docs/AGENTS.md](docs/AGENTS.md) has the full loop and a snippet to paste into your repository's agent instructions. Other MCP clients: run `npx anti-rea mcp-config`.

## Keep it fixed in CI

Copy [examples/workflows/exposure.yml](examples/workflows/exposure.yml). It fails the build on a high-or-worse exposure:

```yaml
- run: npx --yes -p @anti-rea/cli@0.1.0 anti-rea expose dist --out anti-rea-exposure --fail-on high
```

Add `anti-rea assure` to your release job to block anything you declared must never ship.

## What `assure` blocks

| Gate | Blocks when |
|---|---|
| `confirmedCriticalSecret` | A declared server-only secret is in the shipped bytes (matched by sha256; the manifest never holds the secret). |
| `serverOnlyFoundInDistribution` | Code you marked as server-only shipped. |
| `declaredPrivateArtifactShipped` | A source map, PDB, dSYM or other private file shipped. |
| `unconfirmedCredentialLead` | A credential in one of 35 provider formats (AWS, GitHub, Stripe, OpenAI, Anthropic, private keys…) ships undeclared. |
| `reverseEngineeringAidShipped` | Debug info, local symbols, original source or unminified code ships, or Electron DevTools or insecure `webPreferences` are on. |
| `platformHardeningViolation` | Signing, hardened runtime, bundle seals, Electron fuses, ASAR integrity or Authenticode don't match what you declared. |
| `requiredLaneInconclusive` | Something couldn't be inspected. **Unreadable content is a gap, never a silent pass.** |

Exceptions must name an owner, a scope, a rationale and an expiry, and they stay visible in the report. There is no aggregate score: a score of 82/100 can sit next to an exposed critical secret. The full list of gates, the manifest format and the known gaps are in [docs/REFERENCE.md](docs/REFERENCE.md).

## Evidence

Every benchmark was **pre-registered, frozen by hash and run once**. Misses are published along with the wins.

| Measure | Result |
|---|---|
| `expose` accuracy, on 240 real Go, C and JS/Electron builds | **96.6%** [94.8, 98.0] (post-hoc; 97.0% as registered) |
| False positives on hardened builds | **0 of 333** |
| Native debug info and symbols (ELF, PE, Mach-O), against an independent reference | **100%** |
| Source maps / `openDevTools()` calls | **66/66** / **43/43** |
| Robustness | No crash on any of 101 installed real apps |
| `assure` secret gate vs tuned TruffleHog (N = 260) | **91.5% vs 81.2%**, p = 0.0013 |
| macOS signing checks vs `codesign` | 145/145 cdhashes, 25/25 tamper cases agree |

**What it doesn't claim:**
- `expose` is **as accurate as** a careful expert checklist built from llvm tools and regexes (p = 0.54), not more accurate. Its edge is doing that checklist in one command, with attribution, grading and fixes.
- Every `expose` miss is one documented gap: a `webPreferences` value passed through a variable.
- Anti-REA never says an app "cannot be reverse engineered". It makes scoped statements about the bytes it inspected.

The full results, protocols, the disclosed harness defect and how to reproduce every number are in [docs/EVIDENCE.md](docs/EVIDENCE.md).

## Documentation

| | |
|---|---|
| [docs/REFERENCE.md](docs/REFERENCE.md) | CLI, architecture, every gate, the manifest and policy format, safety properties, known gaps |
| [docs/EVIDENCE.md](docs/EVIDENCE.md) | Benchmarks, calibration, test coverage, and how to reproduce them |
| [docs/AGENTS.md](docs/AGENTS.md) | Agent workflow and MCP tools |
| [docs/REA-COVERAGE.md](docs/REA-COVERAGE.md) | Coverage for each format |
| [CHANGELOG.md](CHANGELOG.md) · [SECURITY.md](SECURITY.md) | Release notes · reporting a vulnerability |

## License

Proprietary. © Anti-REA authors. See [LICENSE](LICENSE). Every secret in the fixtures and benchmark corpus is synthetic.
