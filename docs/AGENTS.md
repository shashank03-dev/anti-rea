# Anti-REA for coding agents

Anti-REA answers one question about a build, before it ships:

> If someone ran a reverse-engineering tool on this release, what would they recover, which of it can we
> avoid, and what exactly do we change?

Your coding agent does the fixing; Anti-REA tells it what to fix and confirms the fix landed. Everything
Anti-REA does is **static, read-only and offline**: it reads the release bytes, never runs or modifies them, and
makes no network calls. It never claims an app "cannot be reverse engineered". Hardening raises the cost of
recovery; it does not make shipped code unrecoverable.

## Set up (once)

```bash
npm install --save-dev anti-rea
claude mcp add anti-rea -- npx -y -p anti-rea anti-rea-mcp
```

`npx anti-rea mcp-config` prints the same registration for other MCP clients (Cursor, VS Code, Windsurf, …).

## The loop

1. **Build** the release the way you ship it (an `.app`, `.exe`, `.apk`, `dist/` folder or installer).
2. **Ask** your agent: *"Run `expose_release` on `dist/` and fix every avoidable owner finding in our build configuration."*
3. The agent reads `summary.ownerMaxGrade`, works the **owner** findings first, and applies each `remediation`.
   These are standard toolchain settings, such as `strip -S`, `-ldflags="-s -w"`, building without `sourcesContent`,
   `contextIsolation: true` or the Electron fuses. The `checklist` groups them into one action per fix.
4. **Rebuild and re-run.** The fix is done when the finding is gone, not when the config changed.
5. **Gate it.** Once clean, `anti-rea init dist` and `anti-rea assure` turn the result into a release gate that
   blocks any regression (see the README quick start).

## Paste this into your repository's agent instructions

Add to `CLAUDE.md`, `AGENTS.md` or your agent's rules file:

```markdown
## Release hardening (Anti-REA)

- Before tagging a release, build it and run `npx anti-rea expose <build output> --fail-on high`
  (or the `expose_release` MCP tool). Fix owner findings by changing the build configuration, never
  by editing the built artifact, then rebuild and re-run until the owner grade is acceptable.
- Never ship source maps, dSYM/PDB files or original sources. Upload maps and symbols to the
  error-tracking or symbol server instead.
- Third-party findings belong to dependencies: report them, don't patch vendored binaries.
- `npx anti-rea assure --manifest anti-rea.manifest.json --policy anti-rea.policy.json` must exit 0
  before release. Exit 2 means blocked; read the reasons it prints. Add a policy exception only with
  a named owner, a rationale and an expiry date, and only when a human approves it.
- Report `coverage.opaque` honestly: those files were not inspected, so their exposure is unknown, not zero.
```

## Tools (MCP server `anti-rea-mcp`, read-only)

- **`expose_release`** is the main tool. Input is `{ path }` (an `.app`, `.apk`/`.ipa`/`.exe`, a directory or a
  single file) or `{ manifest }`. It returns the exposure report (schema `anti-rea/exposure/v1`):
  - a product profile;
  - findings by attack surface, owner first and third-party collapsed;
  - a deduplicated hardening checklist;
  - coverage, with every uninspected file named;
  - the REA → Anti-REA matrix.
- **`inventory`** lists every shipped file, including nested archive entries, with sha256.
- **`inspect`** returns platform facts (signing, bundle seals, Electron fuses, Authenticode) and reverse-engineering aids.
- **`analyze_artifact`** runs the analyzers over a single file.

## Reading the report

- **Grades** come from a fixed rubric (attack surface → severity), and analyzers never invent one. `maxGrade` is the
  **maximum**, never an average, so a critical cannot hide.
- **`origin`**: `owner` or `third-party`. Attribution is deliberately conservative, so a vendored component is
  sometimes labelled owner, never the reverse.
- **`avoidable`**: `true` when a toolchain setting removes the finding. Inherent findings (Objective-C/Swift
  metadata, Go `pclntab`, IL2CPP `global-metadata.dat`) can only be reduced, for example by obfuscation.
- **Secrets are never printed.** Build metadata that can carry them (Go `-ldflags -X`, `KEY=…` pairs, model
  `__metadata__`) is redacted to a preview that cannot be reversed.

## How accurate is it?

See [bench/v7/RESULTS-eval.md](../bench/v7/RESULTS-eval.md): a pre-registered benchmark, run once, on real builds of
Go, C and JS/Electron code, scored against an independent reference checker. Its scope, its losses and its
predicted misses are reported there in full.
