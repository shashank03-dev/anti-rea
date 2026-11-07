import type { Origin } from "./types.js";

/**
 * Owner vs third-party attribution (v0.8, plan item 5).
 *
 * In v0.7 calibration most of the native signal came from vendored code (node-gyp addons, Sparkle,
 * Lottie, ffmpeg): a launcher drowns if those rank with their own code. Every finding is attributed
 * owner or third-party, so owner findings rank first and third-party findings collapse into counts.
 *
 * Attribution is deliberately conservative — a wrong "third-party" HIDES an owner finding in a rollup,
 * which is worse than a wrong "owner". So:
 * - patterns are matched against the path RELATIVE to the release root (a release directory that happens
 *   to be called `vendor` or `flutter_app` must not make every finding third-party);
 * - vendored components are recognised by exact file / framework names, never by name prefixes;
 * - a bundled framework or helper is third-party when its CFBundleIdentifier does not share the app's
 *   reverse-DNS prefix (`vendorRoots`, computed by the lane from the shipped Info.plists).
 */

export interface ProductProfile {
  name: string;
  version: string;
  readonly platforms: string[];
  readonly frameworks: string[];
  readonly languages: string[];
  /** Reverse-DNS prefix of the app bundle id (e.g. "com.acme"). */
  bundleIdPrefix?: string;
  /** Bundle directories (frameworks, XPC services, plug-ins) whose bundle id is not the app's. */
  readonly vendorRoots: string[];
}

export function emptyProfile(name = "(unknown)", version = "(unknown)"): ProductProfile {
  return { name, version, platforms: [], frameworks: [], languages: [], vendorRoots: [] };
}

/** Flatten the container separator and drop the release-root label (the first segment). */
function relative(path: string): string {
  const f = path.replace(/!\//g, "/");
  const i = f.indexOf("/");
  return i === -1 ? f : f.slice(i + 1);
}

/** Dependency trees and vendored runtimes: everything under them is third-party. */
const VENDOR_DIR = [
  /(?:^|\/)node_modules(?:\.asar(?:\.unpacked)?)?\//i,
  /(?:^|\/)(?:vendor|third_party|third-party|Pods)\//,
  /(?:^|\/)(?:site|dist)-packages\//i,
  /(?:^|\/)lib\/python3[.\d]*\//i,
  /(?:^|\/)base_library\.zip\//i,
  /(?:^|\/)(?:jre|jdk)\//i,
  /(?:^|\/)\.cargo\/registry\//,
  // A Chromium extension packaged under its Chrome Web Store ID (32 letters a–p) is a store-published
  // build copied into the app — e.g. React DevTools (`fmkadmapgofadopljbjfkapdkoienihi.crx`) bundled by
  // Electron apps. The ID is an exact structural form, not a name prefix. An owner-built extension
  // shipped as `my-extension.crx` (or unpacked) stays owner.
  /(?:^|\/)[a-p]{32}\.crx\//,
];

/** Known vendored components, by exact file or bundle name (never by prefix). */
const VENDOR_NAME = [
  // Electron / Chromium runtime
  /(?:^|\/)Electron Framework\.framework\//,
  /(?:^|\/)(?:lib)?ffmpeg\.(?:dll|dylib|so)$/i,
  /(?:^|\/)lib(?:EGL|GLESv2)\.(?:dll|dylib|so)$/i,
  /(?:^|\/)(?:vk_swiftshader|libvk_swiftshader)\.(?:dll|dylib|so)$/i,
  /(?:^|\/)(?:d3dcompiler_\d+|vulkan-1)\.dll$/i,
  /(?:^|\/)(?:v8_context_snapshot(?:\.\w+)?|snapshot_blob|icudtl)\.(?:bin|dat)$/i,
  /(?:^|\/)chrome_(?:100|200)_percent\.pak$|(?:^|\/)resources\.pak$|(?:^|\/)chrome_crashpad_handler(?:\.exe)?$/i,
  // Mac updater / utility frameworks
  /(?:^|\/)(?:Sparkle|Squirrel|Mantle|ReactiveObjC|ReactiveCocoa|Starscream|Alamofire|SnapKit|Lottie)\.framework\//,
  /(?:^|\/)lib[Ll]ottie\.(?:dylib|so)$/,
  // Engines shipped as prebuilt runtimes
  /(?:^|\/)UnityPlayer\.(?:dll|dylib|so)$/i,
  /(?:^|\/)lib(?:unity|main)\.so$/,
  /(?:^|\/)(?:libflutter\.so|flutter_windows\.dll)$/,
  /(?:^|\/)Flutter(?:MacOS)?\.framework\//,
  // MSVC / UCRT redistributables
  /(?:^|\/)(?:vcruntime\d+(?:_\d+)?|msvcp\d+(?:_\w+)?|ucrtbase|concrt\d+|api-ms-win-[\w-]+)\.dll$/i,
  // .NET shared runtime, Unity engine and common NuGet assemblies
  /(?:^|\/)(?:coreclr|clrjit|hostfxr|hostpolicy|mscorlib|netstandard|System(?:\.[\w]+)*|Microsoft\.[\w.]+|Mono\.[\w.]+|UnityEngine(?:\.[\w]+)*|Unity\.[\w.]+|Newtonsoft\.Json|Serilog(?:\.[\w]+)*|NLog|AutoMapper|Polly|Grpc\.[\w.]+|Google\.Protobuf|Avalonia(?:\.[\w]+)*|SkiaSharp|HarfBuzzSharp)\.(?:dll|so|dylib)$/,
];

export function attribute(path: string, profile: ProductProfile, hint?: Origin): Origin {
  const rel = relative(path);
  for (const re of VENDOR_DIR) if (re.test(rel)) return "third-party";
  for (const re of VENDOR_NAME) if (re.test(rel)) return "third-party";
  const flat = path.replace(/!\//g, "/");
  for (const root of profile.vendorRoots) if (flat === root || flat.startsWith(`${root}/`)) return "third-party";
  return hint === "third-party" ? "third-party" : "owner";
}

/** True when a bundle id belongs to the app whose reverse-DNS prefix is `prefix` (case-insensitive). */
export function sameVendor(bundleId: string, prefix: string): boolean {
  const id = bundleId.toLowerCase();
  const p = prefix.toLowerCase();
  return id === p || id.startsWith(`${p}.`);
}
