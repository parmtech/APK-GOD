# Capability status — APK-GOD 0.2

This is a functionality comparison, not a claim that all code or features of a reference project have been incorporated. The original product code calls embedded library APIs; none of the twenty reference CLIs are launched. "Implemented" means the named slice exists, not full upstream parity.

The feature-level acceptance inventory is tracked in [FEATURE_MATRIX.md](FEATURE_MATRIX.md), with machine-readable records in [feature_ledger.json](feature_ledger.json). M00 is complete for the bounded 0.2 commitments named here and in the first-party product records: 66 reference-feature rows plus 14 product rows, with candidate and deferred scope visible. The inventory uses twenty exact source-study snapshots, not release/dependency pins. It is not an exhaustive upstream audit, completion percentage or proof that each candidate behavior has passed acceptance.

| Reference project | Capability represented in APK-GOD now | Material remaining scope |
|---|---|---|
| JADX | Java-like reconstruction, class/method/source index through embedded DAD | JADX-specific decompiler passes, Kotlin/resource presentation and full JADX parity |
| Apktool | Binary XML/resource decoding and DEX instruction listings | Reassemblable smali, full resource rebuild, APK rebuilding and signing |
| Frida | Direct instrumentation API, selected process/module observations and native call counters | Actual Android runtime verification; broad hook authoring/debugger UX |
| Ghidra | Native structures, instructions, CFG and bounded C-like reconstruction through embedded engines | Ghidra's full analysis passes, datatype tooling, processor coverage and interactive workflows |
| mitmproxy | Sanitized HAR import, endpoint structures and evidence correlation | Live HTTP/TLS interception, replay, protocol addons and capture collection |
| MobSF | Package/code/native evidence and a unified report | Full scanner rule coverage, complete dynamic analysis and broad mobile platform support |
| Androguard | Direct 4.1.3 DEX/AXML/ARSC/DAD APIs with common records | Complete upstream API surface, arbitrary transformations and all experimental features |
| Objection | Selected native runtime observations through embedded instrumentation | Objection's interactive exploration modules and their device validation |
| APKiD | Bounded package/DEX/native inventory and checksums | APKiD packer/compiler rules; its rules are not copied into the original MIT core |
| Bytecode Viewer | Own source/index/report UI and Java-like reconstruction | Multiple JVM decompiler choices, bytecode editing and full JAR browsing |
| smali / baksmali | DEX instruction inspection and basic-block graphs | Full syntax-compatible assembly/disassembly and round-trip DEX rebuild |
| dex2jar | Readable DEX methods and source evidence | DEX-to-JVM-class translation and working JAR output |
| radare2 | ELF metadata, imports/exports, disassembly and native models | Full command language, patching, interactive debugging and target coverage |
| Cutter | Original native/source workbench views and exports | Full Rizin-backed interactive analysis/debugger experience |
| angr | Embedded native CFG, bounded C-like reconstruction and goal-directed symbolic models | Full symbolic execution configuration, all analyses and completeness guarantees |
| LIEF | Direct bounded ELF structures, dependencies and symbols | Mutation/rebuilding and its full executable-format API surface |
| LLDB | Explicit selected-process observations via another embedded runtime engine | LLDB breakpoints, stepping, expression evaluation and full debugger semantics |
| Quark Engine | Original capability hypotheses from static call patterns and evidence links | Quark's complete rule engine, rulesets and malware analysis parity |
| drozer | Manifest component/permission inventory and exported flags | Device-level IPC probing, provider interaction and all exploration modules |
| apk-mitm | Imported traffic evidence and static network candidates | APK transformation, certificate modifications, rebuild and device network validation |

## Original product functionality

APK-GOD supplies its own bounded transactions, normalized evidence graph, source/offset mapping, functionality hypotheses, APK v2 cryptographic verifier, local UI/history, report comparison, batch control, exports and optional AI projection. Upstream algorithms remain credited and separately licensed. The product does not claim that changing or optimizing upstream code erases its origin.

## Readiness gates

The project cannot be described as meeting the full twenty-project goal until the broader requested features have concrete acceptance cases and corresponding implementation evidence; the 0.2 inventory bounds only the commitments listed here. Remaining gates include a configured Android runtime, full rebuild/round-trip testing, proxy collection, native debugger behavior, real Windows installation tests, obfuscation/packing samples, and benchmarks against the exact source APK/build pair supplied by the owner.

The owner's Tong Radio APK was reserved for later benchmarking. It was not silently substituted for a test fixture during this build.

## Coverage labels

- `completed`: the particular bounded engine step completed without a reported limitation; it does not mean complete app understanding.
- `partial`: a parser, scope, output, time or other recorded limit affected the step.
- `not-applicable`: the package had no relevant input for that step.
- `failed` / `unsupported`: the check did not succeed or is outside its implemented support.
- `static-observed`: evidence was present in the file or decoded representation.
- `runtime-imported`: a supplied capture contained an observation; association with the APK is not independently established.
- `inferred` / `ai-inferred`: an interpretation, never silently upgraded to observed behavior.
- `unknown`: missing evidence or verification.

See `analysis.json` for the exact run's limits and counts. Installation/availability is reported separately from actual execution and validation.
