# Security policy

Anti-REA parses untrusted release bytes (archives, executables, source maps, model files), so a parser bug in it is
a security bug.

## Reporting a vulnerability

Report it privately through GitHub's **Security → Report a vulnerability** form on this repository, or contact your
Anti-REA licensing contact. Please don't open a public issue.

Include the Anti-REA version (`anti-rea --version`), the command you ran, and, if you can, a minimal file that
reproduces the problem. Never send production secrets: Anti-REA fingerprints secrets with sha256, and a report
needs only the fingerprint.

We aim to acknowledge reports within 3 business days and to ship a fix, or a mitigation, for confirmed issues in
supported versions.

## What is in scope

- Crashes, hangs or unbounded memory use on crafted input, such as decompression bombs or malformed headers.
- Any path by which a secret value reaches a report, log or attestation in plaintext.
- A false **pass** of the release gate on content Anti-REA claims to cover.
- Anything that makes the read-only MCP server write, execute or reach the network.

## Design properties we defend

- Read-only, in-memory expansion with size, entry-count and depth limits; nothing is extracted to disk.
- No network access and no execution of inspected content.
- Secrets are stored as sha256 fingerprints only; reports carry redacted previews.
- Uninspectable content is a coverage gap, never a silent pass.
