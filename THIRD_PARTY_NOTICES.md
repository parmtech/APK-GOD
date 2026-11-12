# Third-party notices — APK-GOD 0.2

This record was prepared from the installed development environment and selected upstream source files on **2026-11-12**. It identifies software used by APK-GOD and important license distinctions. It is not a complete software bill of materials or a certification that a future bundled binary satisfies every redistribution requirement.

## Scope of the project's MIT license

[LICENSE](LICENSE) applies to APK-GOD's original framework, interface, evidence handling and reporting code. It does not relicense embedded engines, installed dependencies, upstream reference repositories, their trademarks, or code reconstructed from an analyzed application. Calling a library through an APK-GOD interface does not change its origin or license.

Dependencies are installed separately through the extras in [pyproject.toml](pyproject.toml). The twenty source-study repositories are recorded, with exact commits and primary license links, in [docs/SOURCE_REVIEW.md](docs/SOURCE_REVIEW.md). Their presence in that record does not mean their complete code or features are included in APK-GOD.

## Principal embedded engines

The following versions were observed in the local Python 3.12 development environment. Paths under `site-packages` identify primary installed evidence; their installation prefix varies between machines.

| Component | Observed version | License evidence | APK-GOD use |
|---|---|---|---|
| Androguard | 4.1.3 | Apache License 2.0, stated in the installed `androguard/decompiler/decompiler.py` header and named package license; the inspected upstream `LICENCE` also contains Apache-2.0 | APK, binary XML, resources, DEX analysis and DAD reconstruction |
| LIEF | 0.17.6 | Apache License 2.0 in installed metadata and the inspected upstream `LICENSE` | ELF structures, symbols and dependencies |
| Capstone | 5.0.9 | BSD 3-Clause in `capstone-5.0.9.dist-info/LICENSE.TXT` | Native instruction decoding |
| Frida Python bindings | 17.26.2 | wxWindows Library Licence 3.1 in `frida-17.26.2.dist-info/licenses/COPYING`; matching text in inspected Frida and frida-python source `COPYING` files | Explicitly requested device/process observation |
| angr | 9.3.4 | BSD 2-Clause in `angr-9.3.4.dist-info/licenses/LICENSE` | Optional native control-flow recovery, reconstruction and symbolic models |

Androguard's installed metadata contains an inconsistent “Other/Proprietary” classifier. The named license and inspected primary source license text state Apache-2.0; this record does not treat the classifier as a replacement license. The inspected reference checkout is a different source snapshot from the installed 4.1.3 distribution.

The angr license identifies The Arizona Board of Regents, Emotion Labs, LLC, Microsoft Corporation and The Regents of the University of California as copyright holders. The complete upstream notices and disclaimers remain applicable. Other components' complete copyright notices are retained in their own distributions and must accompany redistribution as required by their licenses.

## Frida's license and inspection boundary

The installed Frida binding and both inspected source `COPYING` files use the **wxWindows Library Licence 3.1**, not APK-GOD's MIT license. That text incorporates GNU Library General Public Licence terms with an exception permitting binary object-code works based on the library to be distributed under the distributor's own terms. The exception has qualifications, including treatment of added GPL/LGPL code and modifications; preserve the actual license and exception text rather than replacing them with this summary.

The retrieved Frida checkout did not contain populated `frida-core` and `frida-gum` subprojects. This inspection therefore does not establish the complete licensing of everything inside a prebuilt Frida native binary. `frida-tools` was installed in the development environment but is not an APK-GOD CLI integration or a declared direct extra. Androguard can itself install the Frida binding transitively; selecting the static-analysis extra does not imply only static-analysis packages will be installed.

## Important symbolic-engine dependencies

The optional symbolic stack has licenses beyond angr's BSD license:

| Component | Observed version | Primary evidence and distinction |
|---|---|---|
| PyVEX / LibVEX | 9.3.4 | Installed metadata declares **BSD-2-Clause AND GPL-2.0-or-later**. The BSD wrapper license is in `pyvex-9.3.4.dist-info/licenses/LICENSE`; GPL material is in `licenses/pyvex_c/LICENSE` and `licenses/vex/LICENSE.GPL`. `licenses/vex/LICENSE.README` identifies LibVEX as GPL version 2 or later. |
| Pypcode | 4.1.0 | Installed metadata declares **BSD-2-Clause AND Apache-2.0 AND Zlib**. See `pypcode-4.1.0.dist-info/licenses/LICENSE.txt` and bundled Ghidra `pypcode/docs/ghidra/LICENSE` and `NOTICE`. This distribution includes Ghidra SLEIGH/processor material even though APK-GOD does not launch the Ghidra application. |
| Claripy, CLE and Archinfo | 9.3.4 each | BSD 2-Clause in each distribution's `licenses/LICENSE`. APK-GOD directly imports Claripy as part of its symbolic implementation. |
| Z3 solver | 4.13.0.0 | Installed metadata states MIT. A standalone license file was not exposed by the installed distribution file list examined during this review. This is metadata evidence, not a completed source/binary notice audit. |

A bundled distribution containing PyVEX/LibVEX must address its applicable GPL source and license requirements. APK-GOD's original-code MIT license must not be presented as the license of the complete optional dependency bundle. Pypcode's Ghidra attribution and NOTICE material must likewise be preserved where applicable.

## Other directly used and selected transitive libraries

| Component | Observed version | Installed license evidence |
|---|---|---|
| cryptography | 50.0.2 | Apache-2.0 **OR** BSD-3-Clause; `cryptography-50.0.2.dist-info/licenses/LICENSE`, `LICENSE.APACHE` and `LICENSE.BSD`. Used by APK signature verification. |
| Loguru | 0.8.0 | MIT; `loguru-0.8.0.dist-info/licenses/LICENSE`. Used for embedded-engine logging control. |
| apkInspector | 1.3.7 | Apache-2.0; `apkinspector-1.3.7.dist-info/licenses/LICENSE`. |
| NetworkX | 3.7 | BSD-3-Clause; `networkx-3.7.dist-info/licenses/LICENSE.txt`. |
| asn1crypto | 1.5.1 | MIT; `asn1crypto-1.5.1.dist-info/LICENSE`. |
| mutf8 | 1.1.0 | MIT; `mutf8-1.1.0.dist-info/licenses/LICENCE`. |
| bitstring | 4.4.0 | MIT; `bitstring-4.4.0.dist-info/licenses/LICENSE`. |
| bitarray | 3.12.3 | PSF-2.0; `bitarray-3.12.3.dist-info/licenses/LICENSE`. |
| pycparser | 3.0 | BSD-3-Clause; `pycparser-3.0.dist-info/licenses/LICENSE`. |
| lxml | 6.1.3 | BSD-3-Clause for the principal project, with separately documented components; see `lxml-6.1.3.dist-info/licenses/LICENSE.txt` and `LICENSES.txt`. |
| pyelftools | 0.33 | Public-domain/Unlicense text with separately licensed bundled Construct material; see `pyelftools-0.33.dist-info/licenses/LICENSE`. |

These are selected observed packages, not the full transitive installation. For example, inspected `uefi_firmware 1.16` metadata and its top-level license wording differ, and that package also requires attention to inline component licenses. This record does not assign one simplified license to its complete contents. Dependency versions and native components can differ across operating systems and installation dates.

## Redistribution and future changes

Preserve the complete applicable license texts, copyright notices, conditions and disclaimers from the actual artifacts being distributed. BSD 3-Clause also limits use of upstream names for endorsement. Apache-licensed distributions retain relevant NOTICE and attribution material and identify modifications as required by that license. Copyleft components retain their applicable source and redistribution requirements; the Frida exception must be considered in its actual wording and scope.

These summaries do not replace those texts. Before distributing a package that bundles third-party wheels, native binaries or source, record the exact artifact set and include its required notices and corresponding source arrangements. A source checkout declaring optional dependencies is not evidence that a future Windows installer or another bundled build has already undergone that review.

No upstream endorsement, blanket license clearance, complete provenance audit or transfer of upstream ownership is asserted. Future copied or modified source must retain its own provenance and terms; optimization and rebranding do not erase them.
