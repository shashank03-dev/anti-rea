# Platform sub-study results — eval set

N = 60 scenarios; frozen 6099fbf6…

| Config | Correct | Accuracy |
|---|---|---|
| AR-1 | 60/60 | 100.0% |
| CS-D | 44/60 | 73.3% |
| CS-T | 52/60 | 86.7% |

| Kind | Truth | n | AR-1 | CS-D | CS-T |
|---|---|---|---|---|---|
| intact | pass | 20 | 20 | 20 | 20 |
| modified-asar | block | 4 | 4 | 4 | 4 |
| added-file | block | 4 | 4 | 4 | 4 |
| no-hardened-runtime | block | 4 | 4 | 0 | 4 |
| modified-info-plist | block | 4 | 4 | 4 | 4 |
| get-task-allow | block | 4 | 4 | 0 | 4 |
| asar-integrity-mismatch | block | 4 | 4 | 0 | 0 |
| modified-code-page | block | 4 | 4 | 4 | 4 |
| modified-resource | block | 4 | 4 | 4 | 4 |
| deleted-resource | block | 4 | 4 | 4 | 4 |
| runasnode-fuse-enabled | block | 4 | 4 | 0 | 0 |

## Hypotheses

- **H12 (platform accuracy): SUPPORTED.** AR-1 correct 60/60 (need ≥95%)
- **H12b (agreement with codesign on clean + tampered): SUPPORTED.** AR-1 and CS-D decisions agree on 44/44 P-CLEAN + P-TAMPER scenarios (need all)
- **H12c (AR-1 vs scripted codesign policy CS-T): SUPPORTED.** AR-1 60/60 vs CS-T 52/60: 8 : 0, exact McNemar p=7.81e-3 (need AR-1 ahead, p<0.01)

## Errors

- CS-D P005 (no-hardened-runtime, truth block): pass
- CS-D P011 (get-task-allow, truth block): pass
- CS-D P012 (asar-integrity-mismatch, truth block): pass
- CS-D P014 (no-hardened-runtime, truth block): pass
- CS-D P018 (get-task-allow, truth block): pass
- CS-D P020 (get-task-allow, truth block): pass
- CS-D P021 (asar-integrity-mismatch, truth block): pass
- CS-D P026 (no-hardened-runtime, truth block): pass
- CS-D P033 (asar-integrity-mismatch, truth block): pass
- CS-D P036 (get-task-allow, truth block): pass
- CS-D P037 (runasnode-fuse-enabled, truth block): pass
- CS-D P039 (asar-integrity-mismatch, truth block): pass
- CS-D P040 (runasnode-fuse-enabled, truth block): pass
- CS-D P046 (runasnode-fuse-enabled, truth block): pass
- CS-D P054 (no-hardened-runtime, truth block): pass
- CS-D P056 (runasnode-fuse-enabled, truth block): pass
- CS-T P012 (asar-integrity-mismatch, truth block): pass
- CS-T P021 (asar-integrity-mismatch, truth block): pass
- CS-T P033 (asar-integrity-mismatch, truth block): pass
- CS-T P037 (runasnode-fuse-enabled, truth block): pass
- CS-T P039 (asar-integrity-mismatch, truth block): pass
- CS-T P040 (runasnode-fuse-enabled, truth block): pass
- CS-T P046 (runasnode-fuse-enabled, truth block): pass
- CS-T P056 (runasnode-fuse-enabled, truth block): pass
