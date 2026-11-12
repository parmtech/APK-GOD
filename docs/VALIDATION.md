# Validation record — APK-GOD 0.2

This record separates a fresh test-suite run from reports retained from earlier local analysis. Passing the listed checks establishes their bounded behavior; it does not establish feature parity with the twenty reference projects. See [CAPABILITIES.md](CAPABILITIES.md) for the remaining scope.

## Current automated test run

On 12 November 2026, the project virtual environment ran:

```bash
.venv/bin/python -m pytest -q
```

Result: **55 passed, 1 skipped in 13.15 seconds**. The validation host used Python **3.12.14**, Linux, x86_64. This is a local test result, not a GitHub Actions result or a Windows installation result.

The skipped test was checked separately using pytest's `-rs` reporting. Its recorded reason was:

> Frida native backend could not start its local helper on this host (idund, signal 11); no runtime observation was completed.

### Resume checkout on Windows — 12 November 2026

This continuation ran from a clean Windows checkout with Python **3.13.17** at `C:\Users\~MaNBiR~\dev\python-embed\python.exe`. The `py` launcher and Python 3.12 were unavailable, and there was no project virtual environment. The command `python -m pytest -q -rs` exited before test collection with:

> `No module named pytest`

No Windows project tests ran. This does not supersede or reproduce the Linux result above. M00 ledger structure and the generated Markdown synchronization were checked separately with `python scripts/render_feature_matrix.py` and `python scripts/render_feature_matrix.py --check`.

Installed dependencies and device execution are separate facts. The local availability check found Androguard 4.1.3, LIEF 0.17.6, Capstone 5.0.9, Frida 17.26.2 and angr 9.3.4. Presence of those libraries does not imply that every optional feature or target works.

### What the tests exercise

| Test module | Cases | Evidence and scope |
|---|---:|---|
| `tests/test_native.py` | 10 | Original ZIP, DEX and binary XML fixtures; archive and parser bounds; manifest decoding; DEX calls, basic blocks, instruction output and Java-like reconstruction; ELF metadata and bounded native disassembly. |
| `tests/test_pipeline.py` | 12 | Analysis transactions, exports and no-overwrite behavior; HTML escaping; a local real-APK integration; local dashboard HTTP upload, report/source downloads, persistent history and route guards. |
| `tests/test_evidence.py` | 7 | Stable evidence references and offsets, explicit static/runtime distinctions, bounded and sanitized HAR import, safe source indexing and graph limits. |
| `tests/test_compare.py` | 4 | Package, permission, method and endpoint comparisons; class identity; preservation of partial coverage; report loading. |
| `tests/test_signatures.py` | 9 | Original signed APK-like ZIP fixtures; supported APK v2 signature algorithms; protected-content chunk boundaries; multiple signers; tampering, algorithm order, key mismatch and malformed/unsupported data. |
| `tests/test_symbolic.py` | 5 | Input bounds plus an original compiled C fixture analyzed through angr: CFG, bounded C-like reconstruction and a symbolic input witness; bounded failure is not interpreted as unreachability. |
| `tests/test_ai.py` | 7 | Payload projection/redaction, a local compatible HTTP provider stub, immutable source findings, evidence-ID and response-schema validation, endpoint checks and redirect credential handling. |
| `tests/test_runtime.py` | 2 | Runtime argument/output validation passed. The actual local native instrumentation case was skipped for the host failure above. |

The 56 cases include the one skip. Optional integration cases can skip on another machine when their dependency or separately supplied fixture is absent; inspect that machine's pytest summary.

The symbolic fixture is compiled for analysis and is not executed on the host. Its witness is evidence about the configured symbolic model. The tests do not establish correctness for arbitrary binaries, architectures, operating-system models or path constraints.

The dashboard tests exercise a real local HTTP server. They do **not** run a browser's JavaScript, inspect rendered layout or establish visual/browser compatibility. No completed visual UI validation is claimed in this record.

## Retained real-APK analysis reports

The following figures come from previously generated local `analysis.json` files. They were inspected during this validation, not remeasured as part of the fresh full-suite run. The original reports and downloaded fixture are local validation material and are not bundled in the application repository.

### Fixture identity and provenance

- Filename: `hello-world.apk`; package: `de.rhab.helloworld`, version `1.0` (code `1`).
- Size: **1,722,314 bytes**.
- SHA-256: `f427a0ebe0bca97b9acf6cd2a2a01c37a7d3762841810fc54a7191ec637330b2`.
- Upstream source: [Androguard's pinned test fixture](https://github.com/androguard/androguard/blob/581f7a3251545a97f66ee92b674dd810ee380a00/tests/data/APK/hello-world.apk).
- Upstream commit: `581f7a3251545a97f66ee92b674dd810ee380a00`.
- Git blob identity: `928ce6f670fee375f2d1d0f63d588ae47fef20bc`. The local APK's `git hash-object` result matches the pinned upstream tree entry.

The fixture was parsed as data. These reports do not record installation or execution of the Android app.

| Recorded measurement | Quick profile | Standard profile |
|---|---:|---:|
| Report timestamp, UTC | 2026-11-12 02:54:25 | 2026-11-12 03:10:12 |
| DEX files parsed | 1 / 1 | 1 / 1 |
| Class definitions exported | 1,000 / 2,119 | 2,119 / 2,119 |
| Method definitions exported | 6,000 / 17,143 | 17,143 / 17,143 |
| Static call references exported | 16,962 | 43,099 |
| Instructions exported | 30,000 | 189,694 |
| Methods with CFG output | 5,476 | 15,464 |
| Classes with Java-like reconstruction | 50 | 500 |
| Decoded resource exports | 181 | 254 |
| Native libraries present | 0 | 0 |
| Recorded analysis duration | 4.144 s | 6.997 s |
| Recorded peak RSS | 324,864 KiB | 427,620 KiB |

Sources for these measurements were `validation-quick/analysis.json` and `validation-standard/analysis.json` in the local validation workspace. Both reports identify Androguard 4.1.3, LIEF 0.17.6 and Capstone 5.0.9 for the embedded static analysis.

**Both DEX analyses were partial.** Quick analysis reached resource, class, method, instruction and reconstruction limits. Standard analysis exported all indexed class and method definitions for this fixture, but Java-like reconstruction reached its **500-class limit**. Exporting a method definition or call reference does not prove full semantic recovery, execution coverage, source equivalence or successful rebuilding.

The fixture contains no native libraries, so these APK reports do not validate native APK analysis. Native and symbolic test coverage comes from the separate fixtures described above. Timings describe single retained runs and provide no comparative performance result against upstream tools.

## AI, runtime and platform limits

- **AI:** The provider tests use a local HTTP stub that supplies controlled compatible responses. They verify transport, payload and schema behavior; they do not verify a real model's reasoning quality. No paid or external model-provider test is established by this record.
- **Runtime:** The Frida local helper failed on the validation host. No successful live observation, Android device attachment or native hook count is claimed. A configured compatible device and actual on-device tests remain required.
- **Windows:** Setup/start scripts are present, but no end-to-end Windows installation or execution test is established here. Linux test results do not validate Windows behavior.
- **Browser UI:** HTTP workflow tests passed; no screenshot-based or JavaScript browser validation is established here.
- **Tong Radio:** The owner's APK and its matching source/build pair were reserved for later benchmarking. They have **not** been tested as part of the evidence above.
- **Full functionality:** Reassembly/rebuild/signing, live traffic collection, full debugger behavior, broad runtime modules, packing/obfuscation coverage and complete parity remain outside the demonstrated scope. See the capability matrix.

## Reproduce the applicable checks

Install the desired extras into a local virtual environment, then run:

```bash
python -m pip install '.[full,dev]'
python -m pytest -q -rs
python -m apk_god doctor
```

The optional real-APK case uses `APK_GOD_TEST_APK` when set, or looks for `../reference-fixtures/hello-world.apk` relative to the project. Tests do not download that fixture. When reproducing the recorded fixture run, obtain the exact pinned file above and confirm its hash. A different owner-supplied APK can exercise the integration case, but its results are not directly comparable to the recorded counts.

For a separate measured report, choose a new output directory:

```bash
python -m apk_god analyze path/to/hello-world.apk -o reports/validation-standard --profile standard
```

Inspect `engine_runs`, `engine_analysis.coverage`, `performance` and `limitations` in that run's `analysis.json`. A report export or a green test summary alone does not certify complete application understanding.
