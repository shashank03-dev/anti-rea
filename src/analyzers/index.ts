import type { Analyzer } from "./types.js";
import { nativeMachO } from "./native-macho.js";
import { nativeElf } from "./native-elf.js";
import { nativePe } from "./native-pe.js";
import { jsElectron } from "./js-electron.js";
import { debugFiles } from "./debug-files.js";
import { dotnet } from "./dotnet.js";
import { unityIl2cpp } from "./unity-il2cpp.js";
import { apk } from "./apk.js";
import { flutter } from "./flutter.js";
import { go } from "./go.js";
import { rust } from "./rust.js";
import { pyinstaller } from "./pyinstaller.js";
import { wasm } from "./wasm.js";
import { models } from "./models.js";
import { godot } from "./godot.js";
import { gpu } from "./gpu.js";
import { evm, beam } from "./stubs.js";

/**
 * Analyzer registry, in implementation-priority order (plan "Analyzers"). Priority is launcher value:
 * native code and the desktop/mobile frameworks first, then the long tail of formats, then roadmap
 * stubs. The order also decides report grouping ties.
 */
export const ANALYZERS: readonly Analyzer[] = [
  nativeMachO,
  nativeElf,
  nativePe,
  jsElectron,
  debugFiles,
  dotnet,
  unityIl2cpp,
  apk,
  flutter,
  go,
  rust,
  pyinstaller,
  wasm,
  models,
  godot,
  gpu,
  evm,
  beam,
];

export const ITEM_ANALYZERS = ANALYZERS.filter((a) => a.scope === "item");
export const BUNDLE_ANALYZERS = ANALYZERS.filter((a) => a.scope === "bundle");

export { nativeMachO, nativeElf, nativePe, jsElectron, debugFiles, dotnet, unityIl2cpp, apk, flutter, go, rust, pyinstaller, wasm, models, godot, gpu, evm, beam };
export type { Analyzer } from "./types.js";
