import { looksLikeElf, readElf } from "../codecs/elf.js";
import { looksLikeMachO } from "../codecs/macho.js";
import type { InventoryItem } from "../lanes/types.js";
import type { Analyzer, AnalyzerContext, BundleContext, ProfileTags, RawFinding } from "./types.js";

/**
 * flutter (bundle scope): a Flutter app ships its Dart code as an AOT snapshot next to the engine —
 * `libapp.so` (Android, Linux), `data/app.so` (Windows) or `App.framework/App` (iOS, macOS) — detected by
 * CONTENT (the `_kDartIsolateSnapshotInstructions` snapshot symbol), not by name. Only those candidate
 * files are tested: the engine itself (`libflutter.so`, `Flutter.framework`) references the same symbol
 * names and is third-party. Whether Dart names were stripped by `--obfuscate` is NOT decidable from the
 * shipped bytes, so the finding is detected-only and says so.
 */

const SNAPSHOT_SYMBOL = "_kDartIsolateSnapshotInstructions";
const APP_CANDIDATES = ["libapp.so", "data/app.so", "App.framework/App", "App.framework/Versions/A/App"];
const ENGINE = ["libflutter.so", "flutter_windows.dll", "Flutter.framework/Flutter", "FlutterMacOS.framework/FlutterMacOS", "FlutterMacOS.framework/Versions/A/FlutterMacOS"];

function isDartSnapshot(b: Buffer): boolean {
  if (looksLikeElf(b)) {
    try {
      const e = readElf(b);
      if (e.dynsym.some((s) => s.name === SNAPSHOT_SYMBOL) || e.symtab.some((s) => s.name === SNAPSHOT_SYMBOL)) return true;
    } catch {
      /* fall through */
    }
  }
  // Mach-O App.framework/App (and any candidate whose symbol table did not parse): the snapshot symbol
  // is in the string table. Only app-snapshot candidates reach here, never the engine.
  return (looksLikeMachO(b) || !looksLikeElf(b)) && b.indexOf(SNAPSHOT_SYMBOL) >= 0;
}

function snapshot(b: BundleContext): { item: InventoryItem; dart: boolean | null } | null {
  for (const c of APP_CANDIDATES) {
    const item = b.entry(c);
    if (!item) continue;
    const buf = b.read(item);
    return { item, dart: buf ? isDartSnapshot(buf) : null }; // null: present but unreadable (a gap)
  }
  return null;
}

export const flutter: Analyzer = {
  id: "flutter",
  title: "Flutter Dart AOT snapshot",
  mirrorsRea: "Flutter / Dart snapshot inspection (reFlutter, Doldrums, blutter)",
  scope: "bundle",
  needs: {},

  detect(ctx: AnalyzerContext): boolean {
    if (ctx.scope !== "bundle") return false;
    const b = ctx as BundleContext;
    const snap = snapshot(b);
    if (snap && snap.dart !== false) return true;
    return ENGINE.some((e) => !!b.entry(e));
  },

  profile(): ProfileTags {
    return { frameworks: ["Flutter"], languages: ["Dart"] };
  },

  analyze(ctx: AnalyzerContext): RawFinding[] {
    const b = ctx as BundleContext;
    const snap = snapshot(b);
    if (snap && snap.dart !== false)
      return [{ analyzerId: this.id, rubricId: "symbols/local", title: "Flutter Dart AOT snapshot", recovers: "the compiled Dart app; without build-time obfuscation its class and function names remain in the snapshot, and tools such as blutter/reFlutter extract them. Whether names were stripped is not decidable from the shipped bytes", remediation: "build with `flutter build <target> --obfuscate --split-debug-info=<dir>` (keep the debug info for symbolication)", avoidable: true, path: snap.item.ref.path, coverage: "detected-only", detail: snap.dart === null ? `${snap.item.ref.path} (not readable here)` : snap.item.ref.path }];
    const engine = ENGINE.map((e) => b.entry(e)).find(Boolean);
    if (engine)
      return [{ analyzerId: this.id, rubricId: "symbols/local", title: "Flutter engine present (app snapshot not found)", recovers: "a Flutter app (the engine library ships); its Dart AOT snapshot was not found among the inspected files", remediation: "build with `flutter build <target> --obfuscate --split-debug-info=<dir>`", avoidable: true, path: b.group.root || engine.ref.path, coverage: "detected-only", detail: engine.ref.path }];
    return [];
  },
};
