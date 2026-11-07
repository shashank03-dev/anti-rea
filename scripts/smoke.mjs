#!/usr/bin/env node
// Install smoke test: exercises the package exactly as a customer receives it.
//   1. `npm pack` this checkout (prepack builds it);
//   2. install the tarball into an empty project;
//   3. run the installed `anti-rea` bin (version, expose on the synthetic multi-format release);
//   4. drive the installed `anti-rea-mcp` server through an MCP handshake and one tool call.
// Requires `node fixtures/expose-demo/build.mjs` to have produced fixtures/expose-demo/release.
// Cross-platform (no shell-isms). Exit 0 = every check passed.
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import assert from "node:assert/strict";

const root = resolve(import.meta.dirname, "..");
const release = join(root, "fixtures", "expose-demo", "release");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const win = process.platform === "win32";
const npm = (args, cwd) => execFileSync(win ? "npm.cmd" : "npm", args, { cwd, encoding: "utf8", shell: win });

if (!existsSync(release)) throw new Error(`missing ${release}: run \`node fixtures/expose-demo/build.mjs\` first`);

const work = mkdtempSync(join(tmpdir(), "anti-rea-smoke-"));
try {
  const tgz = npm(["pack", "--silent", "--pack-destination", work], root).trim().split(/\r?\n/).pop();
  const proj = join(work, "customer");
  execFileSync(process.execPath, ["-e", `require("fs").mkdirSync(${JSON.stringify(proj)})`]);
  writeFileSync(join(proj, "package.json"), JSON.stringify({ name: "customer", version: "1.0.0", private: true }));
  npm(["install", "--no-audit", "--no-fund", join(work, tgz)], proj);

  const bin = join(proj, "node_modules", "anti-rea", "build", "src");
  const cli = (...args) => spawnSync(process.execPath, [join(bin, "cli.js"), ...args], { cwd: proj, encoding: "utf8" });

  // The published tarball carries the build and nothing from test/ or bench/.
  const listing = npm(["pack", "--dry-run", "--json"], root);
  const files = JSON.parse(listing)[0].files.map((f) => f.path);
  assert.ok(files.includes("build/src/cli.js") && files.includes("build/src/mcp/server.js"), "tarball is missing the build");
  assert.ok(!files.some((f) => f.startsWith("build/test/") || f.startsWith("bench/") || f.startsWith("fixtures/")), "tarball ships test/bench/fixture files");

  for (const flag of ["--version", "-v", "version"]) {
    const r = cli(flag);
    assert.equal(r.status, 0, `${flag} exit`);
    assert.equal(r.stdout.trim(), pkg.version, `${flag} prints the version`);
  }

  const out = join(work, "report");
  const r = cli("expose", release, "--out", out, "--fail-on", "critical");
  assert.equal(r.status, 2, `expose --fail-on critical should exit 2 on the planted release (got ${r.status}: ${r.stderr})`);
  const report = JSON.parse(readFileSync(join(out, "exposure.json"), "utf8"));
  assert.equal(report.schema, "anti-rea/exposure/v1");
  assert.equal(report.summary.maxGrade, "critical");
  assert.ok(report.summary.owner > 0 && report.checklist.length > 0, "owner findings and a checklist");
  assert.ok(existsSync(join(out, "exposure.md")), "markdown report written");

  const mcp = spawnSync(process.execPath, [join(bin, "mcp", "server.js")], {
    input: [
      { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } },
      { jsonrpc: "2.0", method: "notifications/initialized" },
      { jsonrpc: "2.0", id: 2, method: "tools/list" },
      { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "expose_release", arguments: { path: release } } },
    ].map((m) => JSON.stringify(m)).join("\n") + "\n",
    encoding: "utf8",
  });
  const replies = mcp.stdout.trim().split(/\r?\n/).map((l) => JSON.parse(l));
  assert.equal(replies.length, 3, "one reply per request, none for the notification");
  assert.equal(replies[0].result.serverInfo.version, pkg.version);
  assert.deepEqual(replies[1].result.tools.map((t) => t.name).sort(), ["analyze_artifact", "expose_release", "inspect", "inventory"]);
  assert.notEqual(replies[2].result.isError, true, replies[2].result.content?.[0]?.text);
  assert.equal(replies[2].result.structuredContent.summary.maxGrade, "critical");

  console.log(`smoke: ok — ${tgz} installs, CLI and MCP work (node ${process.version}, ${process.platform})`);
} finally {
  rmSync(work, { recursive: true, force: true });
}
