# APK-GOD

**An integrated Android analysis workbench with its own interface, evidence model and reporting code.**

APK-GOD reads APKs through embedded library APIs. It does not launch a collection of external reverse-engineering tool CLIs. Static analysis works locally without AI or an API key; optional AI explains a deliberately reduced evidence summary.

**Status: 0.2 development build.** The working features below have focused automated coverage. This is not a claim to reproduce every feature of the twenty reference projects, recover every APK's original source, or outperform all upstream engines. The exact implemented scope, remaining capabilities and verification limits are recorded in [docs/CAPABILITIES.md](docs/CAPABILITIES.md) and [docs/VALIDATION.md](docs/VALIDATION.md).

## Continue development

Start with [HANDOFF.md](HANDOFF.md) to resume from the saved checkpoint: it records the product decisions, verified results, environment blockers, reproduction commands and next work. The [development blueprint](docs/BLUEPRINT.md) defines proposed milestones and acceptance gates; [ARCHITECTURE.md](ARCHITECTURE.md) describes the implemented design. Keep these records current when saving the next checkpoint.

## Working functionality

- APK inventory, archive limits, package identity, binary/text manifests, permissions, components, intent filters and compiled resource decoding.
- DEX classes, method definitions, instructions, static call references, basic-block control flow, Dalvik inspection listings and Java-like source reconstruction.
- Native ELF structures, symbols, imports, exports, dependencies and bounded ARM/Thumb/AArch64/x86 instruction decoding.
- Native control-flow recovery, C-like reconstruction and explicitly requested, bounded symbolic path exploration through the optional symbolic engine.
- An original APK Signature Scheme v2 verifier: signer signatures, ordered algorithm checks, certificate/key matching and streaming protected-content digests. It does not assess publisher trust or all Android signature schemes.
- A shared evidence graph and functionality hypotheses with exact source/offset references. Observed package facts, imported captures, inferences and unknowns stay distinct.
- Sanitized HAR import, report comparison, batch analysis and source exports.
- A local dashboard with analysis profiles, persistent report history, dark/light themes and report/source downloads.
- Explicit runtime observation using an embedded instrumentation API. A compatible configured target is required. Native backend failures are isolated from the main app; runtime observation could not be completed on the current validation host.
- Optional compatible AI endpoints, including local models: previewable redacted payload, bounded responses, checked evidence references and separate AI-only annotations.

The first-party framework handles bounds, normalized intermediate data, output identity, evidence relationships, export management and measurement. Mature parsing, decoding and reconstruction algorithms are embedded under their own licenses. Neither branding nor optimization transfers upstream copyright.

## Install

Python 3.12 is the validated runtime. Initial dependency installation needs internet access; ordinary static analysis does not. Use a local virtual environment.

### Linux / WSL

```bash
git clone https://github.com/parmtech/APK-GOD.git
cd APK-GOD
sh scripts/setup.sh
sh scripts/start.sh
```

Open `http://127.0.0.1:8765`. The dashboard accepts APKs up to 128 MiB; the CLI has a 512 MiB input bound and further per-member limits. Large or complex files may produce partial results or exceed a recorded bound.

### Windows PowerShell

```powershell
git clone https://github.com/parmtech/APK-GOD.git
cd APK-GOD
.\scripts\setup.ps1
.\scripts\start.ps1
```

The Windows setup installs static analysis and runtime dependencies. Advanced native symbolic analysis is optional; use Linux/WSL for the currently validated combination. A Windows end-to-end build has not been verified in this environment.

### Choose dependencies

```bash
python -m pip install '.[analysis]'       # embedded static APK/native analysis
python -m pip install '.[runtime]'        # explicit instrumentation API
python -m pip install '.[symbolic]'       # native reconstruction and symbolic models
python -m pip install '.[full]'           # all of the above
python -m apk_god doctor
```

Installing the base project without extras leaves bounded ZIP inspection and text-manifest analysis available; missing binary parsers are recorded rather than silently treated as successful.

## Analyze and export

```bash
apk-god analyze own-app.apk -o reports/run-001 --profile standard
apk-god analyze own-app.apk -o reports/deep-001 --profile deep --timeout 300
apk-god analyze own-app.apk -o reports/traffic-001 --har own-capture.har
apk-god batch ./own-apks -o reports/batch-001 --profile quick
apk-god diff reports/old/analysis.json reports/new/analysis.json -o reports/diff.json
```

Every output directory must be new or empty. Previous analyses are never overwritten. Exports include:

| Artifact | Content |
|---|---|
| `report.html` | Self-contained evidence report and source index |
| `analysis.json` | Package, engines, instructions, coverage and evidence |
| `evidence-graph.json` | Nodes, relationships and source references |
| `source-bundle.zip` | Generated source/listings and engineering artifacts; not the original APK |
| `report.md` | Readable findings and coverage |
| `rewrite-spec.md` | Evidence-backed engineering handoff and unknowns |
| `source/`, `native/` | Decoded resources, reconstructed text and native listings |

`quick`, `standard` and `deep` have explicit limits for classes, methods, instructions, source bytes and processing time. Application-package classes are prioritized before bundled libraries. Read `engine_analysis.coverage` to see exact totals and omissions; a successful report does not mean every part of the app was understood.

## Native exploration

```bash
apk-god binary own-library.so -o reports/native-001 --functions 10 --timeout 180
apk-god binary own-test-binary -o reports/path-001 --find 0x401150 --avoid 0x401170 --steps 50
```

The example addresses are illustrative; use addresses from the loaded image in your own report. A symbolic witness describes a path in a model with explicit assumptions. Failure to find a witness within bounds does not prove unreachability. These commands parse/model the binary and do not execute it on the host.

## Optional AI

Configure a compatible chat-completions endpoint, a model name and a key if required using `APK_GOD_AI_ENDPOINT`, `APK_GOD_AI_MODEL` and `APK_GOD_AI_KEY`. Keep real credentials outside the repository.

```bash
apk-god ai reports/run-001/analysis.json --preview
apk-god ai reports/run-001/analysis.json --output reports/run-001/ai-findings.json
```

The preview is the evidence projection supplied to the model; the request also includes fixed task instructions and the configured model name. It excludes APK bytes, reconstructed source, raw strings and raw network payloads. Redaction reduces exposure but is not a guarantee that arbitrary prose contains no sensitive information. The provider is contacted only by the explicit AI command. AI output does not modify factual findings or execute code. The transport/schema was tested against a local compatible stub; no paid provider call was made during validation.

## Explicit runtime observation

```bash
apk-god runtime devices
apk-god runtime processes --device YOUR_DEVICE_ID
apk-god runtime observe --device YOUR_DEVICE_ID --target YOUR_TEST_PID --seconds 5 -o reports/runtime.json
```

An optional repeated `--hook module-name:exported-symbol` counts calls to selected native exports without collecting arguments or raw memory. Configure a compatible test device/runtime separately. Static APK analysis never starts instrumentation or installs an app. The current validation host could not initialize Frida's local helper, so device/runtime functionality is not described as verified here.

## Tests and source provenance

```bash
python -m pip install '.[full,dev]'
python -m pytest -q
```

Tests generate original DEX, binary XML, signed ZIP and C fixtures. A separately downloaded, pinned upstream example APK is used only as an additional local check; it is not bundled with the application. See [docs/VALIDATION.md](docs/VALIDATION.md) for tested cases and environment restrictions.

The twenty reference repositories were retrieved for targeted source study. [docs/SOURCE_REVIEW.md](docs/SOURCE_REVIEW.md) records exact commits and inspected entrypoints; it does not pretend that every line was reviewed. [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) scopes upstream code, dependencies and license obligations. APK-GOD's original code is MIT-licensed; that does not relicense embedded libraries, transitive dependencies, reference repositories or their trademarks.
