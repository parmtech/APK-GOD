# APK-GOD integrated architecture

## Product decision

The project uses one APK-GOD interface and an original analysis/evidence framework with direct embedded library calls. It does not implement the earlier proposal of launching twenty external tool executables. Downloading reference source, changing names or optimizing code is not evidence of independent ownership or permission to discard its license.

The reference source audit is a design input. Directly reused or derived code retains the applicable provenance and terms. The framework's own original code is kept distinct from upstream engines. No full-feature parity or overall speed superiority is claimed without a matching benchmark.

## Data path

1. The CLI or loopback dashboard creates a fresh job/output directory.
2. An isolated APK-GOD Python worker validates archive structure and bounds, hashes the input and inventories its contents. It never extracts arbitrary archive paths or runs APK code.
3. Binary/text XML decoding and DEX analysis use embedded APIs. Parsed inventory is passed forward rather than rescanned. DEX data becomes a normalized class/method/instruction/call/CFG model.
4. Native ELF structure and instruction decoding use embedded library interfaces; deep native reconstruction has its own explicit function/library/source limits. Standalone native analysis is also available through the bounded `binary` command.
5. Original code verifies APK v2 cryptographic structure and protected-content digests. Trust and other schemes remain separate unknowns.
6. The evidence layer correlates components, code, native structures, URL candidates and optional imported traffic. Deduplicated graph edges retain distinct evidence offsets.
7. HTML/Markdown/JSON reports and generated source bundles preserve coverage, unsupported cases, errors, inference labels and output hashes.

The original input APK is never included in the generated source bundle. Reconstructed code is inspection material, not a guaranteed buildable source project.

## Modules

| Module | Responsibility |
|---|---|
| `inspect_apk.py` | ZIP validation, inventory, XML fields and bounded string discovery |
| `signatures.py` | Original bounded APK v2 verifier using cryptographic primitives |
| `engines.py` | Embedded DEX/resource APIs and common intermediate records |
| `native.py` | Native structures and bounded instruction decoding |
| `symbolic.py` | Embedded native CFG, decompilation and bounded path models |
| `analysis.py`, `binary.py` | Own worker isolation, deadlines, fresh outputs and exports |
| `evidence.py` | Evidence graph, source references, HAR projection and hypotheses |
| `compare.py` | Deterministic identity, permission, component, class, method and call differences |
| `runtime.py` | Explicit embedded instrumentation with crash containment |
| `ai.py` | Minimal AI projection, transport and reference validation |
| `report.py` | Escaped self-contained reports |
| `server.py`, `static/index.html` | Loopback application, jobs, history and branded interface |

## Optimizations implemented

- Share the package inventory across later stages.
- Prioritize the app namespace for reconstruction under bounded budgets.
- Use one shared DEX analysis graph for cross-references and class reconstruction.
- Stream input hashing and v2 content digest computation instead of loading entire APKs for those tasks.
- Deduplicate evidence nodes/relationships while retaining bounded distinct locators.
- Cap source bytes, instructions, methods, graph size, library count and parser duration; report every cap.
- Use compiled parsing/disassembly libraries where appropriate rather than replacing tested algorithms with an unmeasured rewrite.

The measured run time and peak memory are properties of an individual run. They are not a benchmark proving this product faster or more accurate than all reference projects.

## Runtime and AI boundaries

Static analysis does not invoke a remote provider, attach to a process or execute an APK. Explicit runtime commands use a selected device/process and run the native backend in an APK-GOD worker. Optional AI receives a reduced evidence projection, cannot run tools, and cannot upgrade an inference into a verified fact. An evidence ID check establishes attribution existence, not semantic truth.

## Worker containment and limits

Own Python workers give hard wall-time cancellation and native-crash containment. POSIX workers also apply CPU and address-space bounds. They are not a general hostile-code sandbox, and no claim is made that every native parser vulnerability is prevented. Windows workers have wall-time/process isolation; Windows end-to-end compatibility has not yet been verified in this environment.

## Remaining scope

Full source rebuilding/signing, live proxy collection, complete interactive native debugging, anti-obfuscation parity, dynamic Android instrumentation verification, source-level equivalence benchmarks and full feature coverage of twenty mature projects remain separate deliverables. The explicit [capability matrix](docs/CAPABILITIES.md) is authoritative for this development build.
