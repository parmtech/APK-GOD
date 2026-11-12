# APK-GOD development blueprint

**Planning baseline: 12 November 2026, version 0.2 development build.** This document describes proposed remaining work. None of its milestone gates should be treated as passed merely because the roadmap exists.

Use [HANDOFF.md](../HANDOFF.md) for the resume checkpoint, [ARCHITECTURE.md](../ARCHITECTURE.md) for the current design, [CAPABILITIES.md](CAPABILITIES.md) for implemented scope, and [VALIDATION.md](VALIDATION.md) for evidence already obtained. If the handoff location changes, retain this blueprint's milestone IDs.

## Product target and present boundary

Build one APK-GOD product that provides the requested functionality of the twenty reference projects through its own interface, shared analysis model and implementation. The architecture uses embedded library APIs where appropriate. Launching twenty external tool CLIs behind buttons does not meet that product decision. Upstream or derived code retains its provenance and applicable license.

The current build supplies bounded static APK/DEX/native analysis, evidence correlation, reporting, source exports, comparison, a local dashboard and optional AI explanation. The recorded test result is 55 passed and one runtime test skipped. The capability matrix identifies substantial missing functionality. This baseline does not establish full parity, superiority, original-source recovery or Windows/device readiness.

**First expand the full feature acceptance inventory.** A precise completion figure would require an agreed denominator and feature-level evidence, which do not yet exist. Downloading a reference repository, installing a library or representing a tool with one related capability does not complete that tool's feature set.

## Milestone order

| ID | Proposed milestone | Depends on | Gate evidence |
|---|---|---|---|
| M00 | Full feature inventory and acceptance cases | Current documents | Versioned feature matrix covering all twenty references |
| M01 | Reproducible installation and real browser verification | M00 | Clean Linux/Windows install records; browser workflow results |
| M02 | Android runtime and evidence integration | M00; configured target | Actual fixture-device observations and lifecycle tests |
| M03 | Resource/DEX round trip, rebuild and signing | M00; M02 for device checks | Rebuilt fixture behavior and independent signature checks |
| M04 | Live network capture and controlled replay | M00; M02 | Known-request capture/replay comparison and cleanup checks |
| M05 | Native interactive debugging and broader analysis | M00; target support defined | Debugger fixture traces and analysis comparisons |
| M06 | Detection/scanner rules and obfuscation corpus | M00 | Versioned rule tests, false-positive results and limitations |
| M07 | DEX-to-JAR and multiple decompiler views | M00 | Valid translation outputs and comparative fixture results |
| M08 | AI quality evaluation and optional assistance | M00; richer evidence as available | Real-model evaluation with evidence and uncertainty checks |
| M09 | Unified product workflows and platform regression | M01–M08 | End-to-end acceptance matrix and release candidate evidence |
| M10 | Owner's Tong Radio benchmark | M09 ready for owner benchmark | Exact source/APK comparison and observed behavior results |
| M11 | Release decision and truthful capability claims | M00–M10 | Closed acceptance ledger, packaging and published limitations |

After M00, independent implementation tracks can proceed in parallel. Device-dependent gates remain open until an actual compatible target is available. A blocked target does not prevent work on independent static, rules, export or UI features.

## M00 — Full feature inventory and acceptance cases

Create `docs/FEATURE_MATRIX.md` and a machine-readable feature ledger. Expand every row of the current capability matrix into named features using pinned upstream versions and their documented behavior. Include the subfeatures currently summarized as “full parity”; do not let that phrase serve as an acceptance test.

Each feature needs a stable ID, reference project/version, expected user action, input/target constraints, output semantics, planned APK-GOD module, provenance/dependency choice, fixture, acceptance command or UI case, and evidence location. Record states such as `proposed`, `implemented-unverified`, `verified-with-limits`, `blocked` and `not-implemented`. Distinguish Android-relevant behavior from broader formats/platforms and keep unimplemented scope visible.

**Gate:** All twenty references have reviewed feature entries and no requested capability is silently dropped. Each candidate release feature has a finite, reproducible acceptance case. Remaining scope questions, unsupported behavior and dependencies are named. Only this inventory can support a later measured coverage claim; the number of tool names is not the denominator.

## M01 — Reproducible installation and real browser verification

Exercise installation from a clean checkout in a fresh virtual environment on Linux and the user's Windows environment. Record OS, architecture, Python/dependency versions, installation outcome and exact commands. Preserve Windows-specific optional dependency restrictions instead of claiming Linux symbolic-engine success as Windows success.

Run the real dashboard in a browser. Test file selection/drop, all profiles, a successful report, malformed-input failure, source download, history after restart, theme persistence, long filenames, small viewport and keyboard access. Validate the generated downloads against the job that produced them. Save screenshots and browser-console/network failures as test evidence where useful.

**Gate:** Declared supported installation paths work from clean state. Core browser actions complete without uncaught errors, preserve the correct job identity and show partial/failed status accurately. Existing HTTP tests continue passing. Explicitly list any untested browser or platform; screenshots alone do not establish workflow correctness.

## M02 — Android runtime and evidence integration

Resolve the current Frida `idund`/signal-11 host limitation by identifying a compatible supported runtime/target configuration. Keep the failure record; installing the same dependency again is not evidence of a fix. Use an original Android fixture with known Java/native calls, components, permissions and lifecycle behavior before considering the owner's app.

Add the inventoried runtime functions through embedded APIs, including selected-process inspection, declared hook capabilities, module/class/method observations and device-level component exploration. Map observations into the shared evidence model with target identity, APK hash/build identity where established, timestamps, symbol locations, instrumentation settings and observed duration. Clearly distinguish runtime observations from imported or static evidence.

**Gate:** Real fixture-device tests cover attachment, expected events/counts, target exit, disconnect, unsupported hooks, deadline and clean detachment. The app survives normal observation; failure cannot terminate the main workbench. Device/backend/OS/ABI coverage is recorded. A local Linux process test does not substitute for Android validation.

## M03 — Resource/DEX round trip, rebuild and signing

Implement the M00-defined resource and bytecode edit/reassembly model, then controlled package rebuild and signing. Preserve the distinction between inspection-only Dalvik listings and syntax-compatible reassemblable output. Use generated fixtures with binary resources, multidex, manifests, native entries and known behavior. Keep original inputs immutable and rebuilt outputs separately identified.

Start with no-op decode/rebuild, then one controlled resource change and one controlled bytecode change. Use disposable test signing keys; record the changed certificate identity and supported signature schemes. Extend verification only with explicit scheme-specific tests. A signature being structurally valid does not establish publisher trust.

**Gate:** Each supported fixture round-trips through parse/edit/rebuild, passes independent package/signature checks, installs on the declared test target and exhibits the expected behavior. Byte-for-byte identity is not required when packaging/signing changes; semantic invariants are checked explicitly. Unsupported resource/opcode/signature cases fail with useful diagnostics rather than producing a claimed-good package.

## M04 — Live network capture and controlled replay

Add explicit capture sessions and replay to a local fixture server, using embedded interfaces and the common job/evidence model. Define supported protocols, test-proxy/CA setup, request association, size limits and cleanup. Use an original test app/server pair that deliberately supports the test configuration. HAR import remains a separate path with its existing association limitations.

Compare captured metadata to a known request log. Test redirects, repeated requests, timeouts, bodies within configured limits, malformed input, session interruption and sensitive-data handling. Keep offline analysis free of implicit capture/replay. Show what a selected replay will send and where it will go.

**Gate:** The fixture's expected requests/responses can be matched to captured evidence and deliberately replayed to the fixture server. Stop/cancel closes listeners and restores session-owned configuration. Unsupported TLS/protocol situations remain explicit; “no captured traffic” is not interpreted as “no network behavior.”

## M05 — Native debugger and deeper binary workbench

Define a supported OS/ABI/backend matrix before expanding native analysis. Build interactive state, breakpoints, continue/step, stack/register/memory views and expression capabilities only where a selected embedded debugger supports them. Keep symbolic-path results separate from real debugger execution. Extend datatype/function views and processor coverage according to M00's inventory.

Use original compiled fixtures with source and symbols, plus stripped variants. Verify source/address mapping, branch behavior, breakpoint hits, stepping, stack frames, expression results, target exit and detach. Record limitations for optimized code and architectures that have not been exercised.

**Gate:** Each declared debugger operation has an observed fixture trace on a declared target. The UI state follows the actual stopped/running/detached process state. Native decompilation is assessed against fixture semantics; readable output alone is not accepted as correct reconstruction.

## M06 — Detection/scanner rules and obfuscation corpus

Implement a versioned rule format, evidence locations, severities/confidence, provenance and rule-update behavior. Map requested APKiD/MobSF/Quark-style capabilities to explicit detection cases without treating simple package inventory as packer or malware detection. Retain applicable terms for reused rules.

Build a pinned corpus of owned or appropriately licensed positive and negative fixtures for compiler/packer markers, manifest/configuration issues, code patterns and selected obfuscation transformations. Record expected results before tuning rules. Add malformed, ambiguous and unsupported examples to prevent overconfident findings.

**Gate:** Each enabled rule has a reproducible positive and negative acceptance case. Corpus results include missed detections, false positives, skipped inputs and bounds. A heuristic finding states its evidence and uncertainty. A broad security or malware verdict is not inferred from passing a few pattern tests.

## M07 — DEX-to-JAR and multiple decompiler views

Define supported DEX/JVM versions and translation semantics, then produce actual JVM class/JAR output for original fixtures. Cover exceptions, generics/annotations, arrays, method resolution and multidex identities as applicable. Distinguish a readable DEX listing from valid DEX-to-JVM translation.

Expose multiple embedded decompiler choices through the shared source index where licensing and integration permit. Preserve engine/version provenance, errors and disagreements. Add Kotlin/resource presentation and bytecode-editing capabilities according to the feature inventory.

**Gate:** Declared JAR outputs parse and pass the applicable JVM verifier; supported fixture behavior matches controlled reference results. Each decompiler view links output to the right input identity and records failures. Compilable reconstructed source is claimed only for cases actually recompiled and behaviorally checked.

## M08 — AI quality and optional assistance

Retain a fully useful offline path. The existing local provider stub verifies plumbing only. Build an evaluation set from known-source fixtures, with expected explanations, evidence links, ambiguous cases and unanswerable questions. Run a configured real local or external model only under the applicable user/provider setup, recording model/version, prompt version and evaluation inputs.

Score factual support, unsupported claims, evidence interpretation, uncertainty and useful omissions. Test untrusted text embedded in APK evidence. If code suggestions or reconstruction assistance are added, keep proposed changes separate from observed facts and require compilation/behavioral checks before claiming equivalence. Do not silently send additional source or traffic beyond the selected AI input scope.

**Gate:** Real-model results have a reproducible evaluation report and predefined acceptable criteria. Offline behavior remains intact when the provider is absent, fails or returns invalid content. AI output cannot promote a hypothesis into a verified fact or change the analyzed input automatically.

## M09 — Unified workflows and release candidate

Bring verified feature tracks into the single APK-GOD interface with common input/target selection, progress, cancellation, errors, evidence links, history and exports. Feature availability must reflect dependencies and supported targets. A feature label must not imply that its entire reference tool has been reproduced.

Run the M00 acceptance ledger against a release candidate on declared Linux/Windows/browser/device combinations. Recheck only affected fixtures plus required release gates after fixes. Validate packaging, clean install, report-schema compatibility and repeatable fixture results. Preserve historical reports and input hashes.

**Gate:** Candidate-scope features pass their end-to-end cases, including failure/cancellation paths. Open blockers and exclusions remain visible. All platform claims have actual evidence. No remaining device/browser/Windows blocker is hidden behind unit-test totals.

## M10 — Tong Radio benchmark, after platform readiness

Keep the owner's Tong Radio APK reserved until M09 establishes that the platform is ready for this benchmark. Then obtain the exact APK and matching source commit/build configuration, record hashes and signing identity, and define expected manifest/components, playback behavior, native dependencies and relevant network activity from the known source.

Run offline analysis first, then explicit runtime/capture checks on a configured test target where required. Compare extracted facts, reconstructed behavior, false inferences, omissions, time and peak memory with the known build. If comparing reference engines, use the same inputs, hardware, feature scope and bounds. Separate AI-assisted results from offline results.

**Gate:** A reproducible benchmark explains what APK-GOD correctly recovered, missed or misinterpreted and why. It supports claims only for the tested build and scope. One app's success does not establish universal parity or superiority.

## M11 — Release decision and continuing scope

Close or explicitly defer each release-candidate acceptance item, retain unresolved whole-product scope, and publish versioned capability/validation/provenance records with the package. Verify clean installation and documentation commands from the packaged result. Separate a usable development release from completion of the full twenty-project target.

**Gate:** Claims match the feature ledger and benchmark evidence. A “full requested functionality” claim requires every requested M00 feature to pass its relevant acceptance case; a narrower release must name its limits. No milestone promises that arbitrary original source, backend code, every upstream feature or universal performance superiority can be recovered or guaranteed.

## Resume instruction

Resume at the first open gate, starting with **M00** unless a later handoff records a verified feature inventory. Read the handoff and current Git state before editing. Preserve existing working modules and test evidence, update the ledger as each feature is verified, and record blockers with the exact target/environment and failure rather than restarting the project or declaring untested work complete.
