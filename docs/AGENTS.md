# Anti-REA for agents

Anti-REA's **exposure** capability answers one question about a shipped build:

> If someone ran a reverse-engineering tool on my release, what would they recover, which of it can I
> avoid, and what exactly do I change?

It is the defensive mirror of a REA-class tool. It is **static, read-only, in-memory, and makes no
network calls**. It never modifies the release, never runs it, and never claims an app "cannot be
reverse engineered" — protection raises cost, it does not make shipped code unrecoverable.

## Tools (MCP server `anti-rea-mcp`)

Register the server (it is read-only):

```
claude mcp add anti-rea -- node /path/to/anti-rea/build/src/mcp/server.js
```

or run `anti-rea mcp-config` for ready-made snippets.

- **`expose_release`** — the main tool. Input `{ path }` (a `.app`, `.apk`/`.ipa`/`.exe`, a directory or
  a single file) or `{ manifest }`. Returns the full exposure report (schema `anti-rea/exposure/v1`):
  a product profile, findings by attack surface with **owner findings first and third-party collapsed**,
  a deduplicated hardening checklist (one action, its files, its grade), coverage (every opaque artifact
  named), and the REA → Anti-REA matrix.
- **`inventory`** — list the release closure (files plus nested container entries) with sha256.
- **`inspect`** — platform facts (signing, bundle seals, Electron fuses, PE Authenticode) and
  reverse-engineering aids (native debug info, debug files, sources).
- **`analyze_artifact`** — run the analyzers over a single file.

## Suggested workflow

1. `expose_release { path: "<the built app or installer>" }`.
2. Read `summary.maxGrade` and `summary.ownerMaxGrade`. Work the **owner** findings first — third-party
   findings belong to your dependencies.
3. For each owner finding, apply the `remediation` (a standard toolchain setting). The `checklist`
   groups these into one action per fix, with the files it touches.
4. Treat `coverage.opaque` honestly: those artifacts were not inspected, so their recoverable surface is
   unknown — not zero.
5. Re-run and confirm the grade dropped.

## Grades

Findings are graded by a fixed rubric (attack surface → severity); analyzers never invent a grade.
`maxGrade` is the **maximum** severity, never an average: it cannot hide a critical. Each finding also
carries `avoidable` (a toolchain setting removes it) vs inherent (e.g. Objective-C/Swift metadata, Go
`pclntab`, IL2CPP `global-metadata.dat`), and `origin` (owner vs third-party).

## Safety

The report never prints secret values. Build metadata that can carry secrets — Go `-ldflags -X`, `KEY=…`
pairs, model `__metadata__` — is redacted to a non-reconstructible preview. Metadata keys and model
architecture names are shown; metadata values are not.
