# REA → Anti-REA coverage

A REA-class reverse-engineering tool takes shipped software apart across many formats. Anti-REA's
**exposure** capability is the defensive mirror: for each format, it reports — statically, read-only —
what such a tool would recover from *your* release and the standard toolchain setting that reduces it.
It never claims an app cannot be reverse engineered; protection raises cost, it does not make shipped
code unrecoverable.

Legend: ✅ parsed and reported · ◍ partial / detected-only · 🗺️ roadmap stub (detected, named as a gap).

| Format / target | What a REA tool recovers | Anti-REA analyzer | Status |
|---|---|---|---|
| Mach-O (macOS/iOS) | DWARF, dSYM, stabs debug map (build paths), local symbols, ObjC/Swift metadata, PIE, signing, `get-task-allow` | `native-macho` | ✅ |
| ELF (Linux/Android) | DWARF, `.symtab`, PIE/NX/RELRO, RUNPATH build paths | `native-elf` | ✅ |
| PE (Windows) | CodeView PDB build path, ASLR/DEP/CFG, Authenticode | `native-pe` + `codecs/pe.ts` | ✅ |
| Electron | insecure `webPreferences`, DevTools, preload IPC surface, source maps, fuses | `js-electron` + aids/platform adapters | ✅ |
| .NET / Mono | CIL decompilable to C#/F#, embedded PDB, Unity `Assembly-CSharp`, obfuscation heuristic | `dotnet` | ✅ |
| Unity IL2CPP | `global-metadata.dat` → C# API, method/field/string names | `unity-il2cpp` | ✅ |
| Android APK/AAB | DEX (jadx), R8 name state, `debuggable`/`allowBackup`, v1-only/unsigned | `apk` + `codecs/axml.ts` | ✅ |
| Flutter | Dart AOT snapshot (`libapp.so`, `App.framework` on iOS/macOS, `data/app.so` on Windows); obfuscation not statically decidable | `flutter` | ◍ detected-only |
| Go | `go version -m` buildinfo (module, deps, VCS, ldflags), pclntab names | `go` | ✅ (ldflags redacted) |
| Rust | cargo-auditable crate graph (ELF `.dep-v0`), rustc version, panic build paths | `rust` | ✅ |
| PyInstaller / Python | `.pyc` modules + entry scripts (pyinstxtractor + decompiler) | `pyinstaller` | ✅ |
| WebAssembly | `name` section, DWARF custom sections | `wasm` | ✅ |
| ML models | GGUF / safetensors / TFLite architecture, tensor names, shapes (keys/arch only) | `models` | ✅ (header-only; runs on gap items) |
| Godot | `.gd` GDScript source, `.gdc` bytecode, pack encryption flag | `godot` | ✅ |
| GPU | PTX source, CUDA fatbin, CUBIN (SASS) | `gpu` | ◍ |
| Source maps / sources | original source text via `sourcesContent`, shipped source files | `debug-files` | ✅ |
| PDB / dSYM / portable PDB | symbols, types, source paths | `debug-files` + `native-macho` | ✅ |
| EVM / Solidity | contract bytecode → decompiled logic | `evm` | 🗺️ stub |
| Erlang / Elixir BEAM | BEAM modules → decompiled logic | `beam` | 🗺️ stub |

## Containers

The release inventory already expands zip/jar/apk/aab/ipa, asar, tar, gzip/xz/lzma/bzip2/zstd/lz4, ar and
UDIF DMGs, so analyzers see nested entries directly. Opaque containers (7-Zip, RAR, MSI, xar `.pkg`, RPM,
squashfs/AppImage, NSIS/Inno installers, encrypted DMGs, APFS) are reported as explicit coverage gaps —
named, not silently skipped — so "recovery from these is UNKNOWN" is stated rather than implied.

## Gaps, honestly

- **Flutter / GPU** are detected-only where obfuscation or the recoverable surface can't be decided from
  the shipped bytes alone.
- **EVM / BEAM** are detected and named as roadmap stubs.
- **Obfuscated** .NET, Unity and Godot artifacts are reported as such (control flow still recoverable as
  IL/bytecode; symbolic readability reduced).
- A negative result is scoped to the analyzed formats and the inspected bytes. It is not a proof that
  nothing is recoverable.
