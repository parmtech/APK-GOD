# APK-GOD: resume handoff

Recorded **12 November 2026** for the **0.2.0 development checkpoint**.

Canonical repository: [parmtech/APK-GOD](https://github.com/parmtech/APK-GOD), branch `main`. This is a resumable development snapshot, not a finished implementation of every feature in twenty reference tools. The commit that introduces this handoff identifies the checkpoint; find it with `git log -1 --format='%H %s' -- HANDOFF.md`.

## Start here in the next session

Read these files before editing:

1. This handoff for the current state and immediate next work.
2. [docs/BLUEPRINT.md](docs/BLUEPRINT.md) for planned milestones and acceptance gates.
3. [ARCHITECTURE.md](ARCHITECTURE.md) for the implemented design and module boundaries.
4. [docs/CAPABILITIES.md](docs/CAPABILITIES.md) for the twenty-project comparison and remaining scope.
5. [docs/VALIDATION.md](docs/VALIDATION.md) for actual test results and their limits.
6. [docs/SOURCE_REVIEW.md](docs/SOURCE_REVIEW.md) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for provenance and dependency scope.

Inspect `git status --short` and the recent log before changing anything. Preserve any later user edits. If this checkout is missing, clone the canonical repository; do not restart the project from an empty folder or depend on this chat being available.

## Product decisions already made

- Build one APK-GOD product with its own interface, intermediate data model, evidence relationships and reporting.
- The owner rejected a dashboard that merely starts twenty external tool executables. The current implementation calls embedded libraries directly and rejects the old external-launcher path.
- Useful static analysis must work without an AI provider or API key. AI is optional and must label its conclusions separately from observed evidence.
- The ambition is the functionality of the twenty reference projects and better usability/performance where demonstrated. That ambition is not an implemented or benchmarked claim.
- Studying or modifying upstream code does not make its original license disappear. Preserve provenance when embedding or adapting code.
- Finish the platform's required functionality before treating the owner's Tong Radio APK and matching source/build as the final benchmark. That owner-specific benchmark has not happened.
- The owner wants real implementation and verifiable results, with a durable GitHub handoff so the work can continue in another session.

## What exists and has evidence

| Area | Current implementation | Verification boundary |
|---|---|---|
| APK structure | Archive bounds, hashes, manifest, permissions, components and resources | Original fixtures and a pinned real APK were parsed |
| DEX | Classes, methods, instructions, call references, basic blocks and Java-like reconstruction | Bounded output; reconstructed code is not guaranteed original or buildable |
| Native binaries | ELF structure, symbols, dependencies and instruction listings | Generated native fixtures; not every processor or binary format |
| Native models | Optional angr CFG, C-like reconstruction and bounded symbolic goals | Controlled compiled fixture; a model witness is not observed Android execution |
| APK signatures | Original APK Signature Scheme v2 verification | Signed synthetic cases and tampering checks; other schemes and publisher trust remain separate |
| Evidence and exports | Evidence graph, hypotheses, sanitized HAR import, comparisons, batch commands, HTML/Markdown/JSON and source bundles | Static evidence and imported traffic stay distinct; HAR import is not live capture |
| Dashboard | Local APK upload, profiles, report history, theme and downloads | HTTP workflow tests passed; browser JavaScript/visual QA is still unverified |
| Optional AI | Reduced payload preview, compatible endpoint transport, response and evidence-ID checks | Local HTTP stub only; no external model quality evaluation |
| Runtime | Embedded Frida device/process observation and selected native counters | Input validation tested; live native observation blocked on the validation host |

Implementation entrypoints: `apk_god/cli.py`, `analysis.py`, `engines.py`, `native.py`, `symbolic.py`, `signatures.py`, `evidence.py`, `server.py`, `runtime.py` and `ai.py`. `apkgod.py` is a compatibility entrypoint.

## Latest verified test result

On Python **3.12.14**, Linux x86_64, the project environment ran:

```bash
.venv/bin/python -m pytest -q
```

Result: **55 passed, 1 skipped in 13.15 seconds**. This was a local run, not a GitHub Actions or Windows result.

The single runtime case was then checked with `-rs`. Its exact skip reason was:

> Frida native backend could not start its local helper on this host (idund, signal 11); no runtime observation was completed.

Do not mark this skip as success or remove the test to obtain a green count. The current host failed before successful observation; Android device validation is also outstanding.

Retained standard-profile evidence from the pinned `hello-world.apk` indexed 2,119 classes, 17,143 methods and 43,099 static call references. Java-like reconstruction reached its 500-class limit. Those retained measurements are historical, partial results; see the validation record for provenance and reproduction details.

The five main installed engines were Androguard 4.1.3, LIEF 0.17.6, Capstone 5.0.9, Frida 17.26.2 and angr 9.3.4. `doctor` reports installation availability, not successful execution of every capability.

## Current Windows resume-host check

On **12 November 2026**, this clean Windows checkout exposed Python **3.13.17** from `[local Python executable]`. `py` and Python 3.12 were not available. A project-local `.venv` was created with `uv`, and `.[analysis,dev]` was installed from the official PyPI index. No restart was performed. On this Python 3.13 Windows host, `.venv\Scripts\python.exe -m pytest -q -rs` completed with **51 passed, 6 skipped in 4.70 seconds**. Skips: Linux-only ELF fixture, optional real-DEX fixture, Frida native hook fixture (Linux-only), and three optional angr cases (angr not installed). This is the observed Windows result for the current host/environment, not a clean Windows 3.12 installation test. The M00 renderer and structural validation also passed; see `docs/VALIDATION.md`.

## Exact next work

**M00 is complete for the bounded APK-GOD 0.2 scope.** The versioned inventory contains 66 reference-feature rows across all twenty source-study snapshots (47 candidate, 19 explicitly deferred) and 14 first-party product rows (13 candidate, one deferred). This denominator covers promises in `docs/CAPABILITIES.md` and first-party 0.2 commitments; it is not a catalog of every upstream feature and supports no parity claim or completion percentage. See `docs/FEATURE_MATRIX.md` and `docs/feature_ledger.json`.

**Next: M01 reproducible installation and real browser verification.** Run a clean Windows environment installation, then exercise the dashboard in a dedicated browser: file selection/drop, all profiles, successful report, malformed-input failure, source download, history after restart, theme persistence, long filenames, narrow viewport and keyboard access. Validate downloads against their job and record browser console/network failures. The existing Python 3.13 suite run is host validation, not the clean-install/browser gate. Do not use the unrelated Opera/cPanel browser session.

**Open downstream dependencies:** SQ-04 Android OS/device/ABI for M02; SQ-07 declared browser/Windows/Python support for M01; SQ-08 exact Tong Radio source/APK/build identity for M10; SQ-09 real model/quality thresholds for M08. Native debugger rows are deferred from 0.2 under SQ-06 until an embedded backend, license and target are chosen.

**Parallel environment work:** establish a compatible, explicitly selected Android test device/emulator and verify Frida process/module observation on an owned test app. Record host/device versions and actual success or failure. Keep static analysis usable while this gate remains blocked.

**Later implementation:** rebuild/round-trip support, live capture/replay, native debugger behavior, packer/compiler corpus, broader runtime inspection and real AI-quality evaluation remain separate deliverables. The Tong Radio comparison remains a later acceptance gate; do not substitute it for fixtures or claim it has been tested.

## Recreate the development environment

Use Python 3.12 for the presently validated combination. A fresh installation needs dependency network access; static analysis then works locally.

```bash
git clone https://github.com/parmtech/APK-GOD.git
cd APK-GOD
python3.12 -m venv .venv
.venv/bin/python -m pip install '.[full,dev]'
.venv/bin/python -m apk_god doctor --json
.venv/bin/python -m pytest -q -rs
.venv/bin/python -m apk_god serve
```

Open `http://127.0.0.1:8765` on that machine. Installation/start scripts also exist under `scripts/`. Windows scripts have not yet received an end-to-end validation. Read README for the different static/runtime and optional symbolic extras.

The real-APK integration case expects `APK_GOD_TEST_APK` or `../reference-fixtures/hello-world.apk`. The fixture is deliberately not committed. Its pinned upstream URL and expected SHA-256 are in the validation record. Missing optional fixtures/dependencies can change the skipped count; report that difference rather than quoting this session's result.

The default system Python in this session did not have pytest. The project `.venv/bin/python` did. Use the project environment when continuing here.

## Local materials, if this environment still exists

- Working checkout: `/workspace/scratch/ac5e0de2a264/APK-GOD`.
- Selected reference source snapshots: `/workspace/scratch/ac5e0de2a264/upstream`.
- Real APK fixture: `/workspace/scratch/ac5e0de2a264/reference-fixtures/hello-world.apk`.
- Earlier reports: `/workspace/scratch/ac5e0de2a264/validation-quick` and `validation-standard`.

These are convenience locations and can disappear. The committed source and documentation are the durable restart point. The source review contains pinned upstream identities; it does not imply every repository file or submodule was downloaded or reviewed.

## GitHub checkpoint procedure

Direct Git reads worked in this session. A direct CLI push failed because no command-line credential was supplied. The connected GitHub integration could create repository objects. If using that route, create a commit with the current remote parent, update `main` with an expected-head check, then fetch it and verify that the remote tree matches the local staged tree. An uploaded Git tree alone is not a published branch commit.

Never force-push over a newer remote change. Do not put credentials, `.venv`, APKs, HARs, private keys, reference source trees or generated analysis bundles into the source commit. The repository ignore rules cover the common cases; inspect the staged paths before publishing.

Before ending a future session, update this handoff with the new verified state, test outcomes, remaining blockers and next concrete action. Save the actual code and docs in GitHub, then verify the remote commit. A plan, a test count or a local file alone is not proof that the checkpoint is saved remotely.

## Ready-to-use resume request

> Continue parmtech/APK-GOD from the current main branch. Read HANDOFF.md, docs/BLUEPRINT.md, ARCHITECTURE.md, docs/CAPABILITIES.md and docs/VALIDATION.md first. Preserve the embedded-engine design and offline mode. Inspect the checkout, reproduce applicable tests, and continue the first unmet acceptance gate. Keep observed facts, inferred behavior and unverified features separate. Do not restart the project or claim complete twenty-tool parity from the existing partial implementation. Save and verify the next code-and-documentation checkpoint on GitHub.

## Preservation checkpoint — 2026-11-12

This draft preserves the combined staged and unstaged working files from the local checkout, based on `main` commit `ea63943981ee2d0072dc1a7e2100f02bc762710e`. The original checkout and index were left unchanged. Machine-local Python paths were omitted from this public copy. Windows Python 3.13 validation of this copy using the existing local environment: `pytest -q -rs` passed 51 tests, with 6 skips (Linux ELF, optional real DEX, Linux Frida hook, and three optional angr cases). `python scripts/render_feature_matrix.py --check` passed, validating 66 reference features and 14 product features. These results do not establish the skipped runtime, symbolic or platform scenarios, full feature completion, or production readiness. Next: review the ledger/evidence changes, validate missing environments and fixtures, and reconcile this draft with current main before merging.
