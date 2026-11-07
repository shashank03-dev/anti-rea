import type { Analyzer, AnalyzerContext, BundleContext, ProfileTags, RawFinding } from "./types.js";

/**
 * unity-il2cpp (bundle scope): Unity's IL2CPP backend compiles C# to native code, but it ships
 * `global-metadata.dat`, which carries every managed type, method, field and string-literal name.
 * Il2CppDumper reads it to reconstruct the C# API and method signatures, so a stock metadata file is a
 * symbols-in-the-clear finding, inherent to the IL2CPP backend. A file present next to GameAssembly /
 * libil2cpp but with a non-stock header magic looks protected, and is reported detected-only. A Mono
 * build (Assembly-CSharp.dll, no global-metadata) is left to the `dotnet` analyzer.
 */

const IL2CPP_MAGIC = 0xfab11baf;
/** IL2CPP native code: Windows, macOS/iOS, Linux and Android names. */
const IL2CPP_NATIVE = ["GameAssembly.dll", "GameAssembly.dylib", "GameAssembly.so", "libil2cpp.so", "UnityFramework.framework/UnityFramework"];
const UNITY_ENGINE = ["UnityPlayer.dll", "UnityPlayer.dylib", "UnityPlayer.so", "libunity.so"];

export const unityIl2cpp: Analyzer = {
  id: "unity-il2cpp",
  title: "Unity IL2CPP global-metadata.dat",
  mirrorsRea: "Il2CppDumper metadata recovery",
  scope: "bundle",
  needs: {},

  detect(ctx: AnalyzerContext): boolean {
    if (ctx.scope !== "bundle") return false;
    const b = ctx as BundleContext;
    return !!b.entry("global-metadata.dat") || [...IL2CPP_NATIVE, ...UNITY_ENGINE].some((n) => !!b.entry(n));
  },

  profile(): ProfileTags {
    return { frameworks: ["Unity"], languages: ["C#"] };
  },

  analyze(ctx: AnalyzerContext): RawFinding[] {
    const b = ctx as BundleContext;
    const meta = b.entry("global-metadata.dat");
    const hasNative = IL2CPP_NATIVE.some((n) => !!b.entry(n));
    const out: RawFinding[] = [];
    if (!meta) return out; // Unity native present but no metadata entry (e.g. Mono-only, or metadata is a gap)
    const bytes = b.read(meta);
    const path = meta.ref.path;
    if (!bytes || bytes.length < 8) {
      out.push({ analyzerId: this.id, rubricId: "symbols/metadata-clear", title: "Unity IL2CPP metadata present (not readable here)", recovers: "IL2CPP global-metadata.dat is present; its header could not be read (it may be a size/stream gap)", remediation: "IL2CPP ships names in global-metadata.dat by design", avoidable: false, path, coverage: "detected-only", detail: path });
      return out;
    }
    const magic = bytes.readUInt32LE(0);
    const version = bytes.length >= 8 ? bytes.readUInt32LE(4) : 0;
    if (magic === IL2CPP_MAGIC && version >= 21 && version <= 39)
      out.push({ analyzerId: this.id, rubricId: "symbols/metadata-clear", title: "IL2CPP global-metadata.dat in the clear", recovers: "every managed type, method, field and string-literal name; Il2CppDumper reconstructs the C# API, method signatures and string table from it", remediation: "inherent to Unity's IL2CPP backend — stock Unity ships this file unencrypted. Third-party metadata encryption raises the cost of recovery but there is no built-in toggle", avoidable: false, path, coverage: "full", detail: `${path}: version ${version}` });
    else
      out.push({ analyzerId: this.id, rubricId: "symbols/metadata-clear", title: "IL2CPP metadata present but not in the stock format", recovers: `a global-metadata.dat whose header magic (0x${magic.toString(16)}) is not the stock 0x${IL2CPP_MAGIC.toString(16)}${hasNative ? ", next to the IL2CPP native code" : ""}; it looks encrypted or obfuscated by a protection`, remediation: "appears protected; verify the protection is intentional and current", avoidable: false, path, coverage: "detected-only", detail: `${path}: magic 0x${magic.toString(16)}` });
    return out;
  },
};
