# CCT Modernization Baseline — 2026-09-11

This document freezes and describes the post-PR-326 Card Conformance Tool (CCT) baseline. It records what was observed; it does not prescribe or implement modernization changes.

Labels used throughout:

- **FACT** — directly established from the tagged source, command output, or generated synthetic evidence.
- **OBSERVED RISK** — a reproducibility, build, test, packaging, or operational concern present in the baseline.
- **UNKNOWN** — the available tooling or hardware did not expose a trustworthy answer.

## 1. Baseline Identity

- **FACT** — Repository: `GSA/piv-conformance`.
- **FACT** — Authoritative baseline branch: `master`.
- **FACT** — Phase-0 documentation branch: `feature/cct-modernization-phase-0-baseline`.
- **FACT** — Commit: `be19a5c59777a70b9a2dffac12dc760437d1f16b`.
- **FACT** — Commit date: `2026-09-11T07:08:36-04:00`.
- **FACT** — Commit subject: `Merge pull request #326 from GSA/feature/auto-package`.
- **FACT** — PR #326, “Automatically package completed test results,” is included. Its tip is `f69998f4c8ca13ef8e3313323da2d1f4341571df`, which is a parent of the merge commit.
- **FACT** — Annotated baseline tag: `cct-modernization-baseline-2026-09-11`.
- **FACT** — Local and remote annotated tag object: `cbd00cdcd564975b808d9e6eabc44065f0d9a611`.
- **FACT** — Local and remote peeled tag target: `be19a5c59777a70b9a2dffac12dc760437d1f16b`.
- **FACT** — `master`, `origin/master`, the Phase-0 branch, and the peeled baseline tag all resolved to the baseline commit after synchronization.

### Worktree safety record

- **FACT** — Before synchronization, the current branch was `feature/cct-modernization-phase-0-baseline` at `f69998f4c8ca13ef8e3313323da2d1f4341571df`; cached `origin/master` was `62e8ebab5362945cdea75b3b825deb3c3acd78de`.
- **FACT** — Initial `git status --short`, staged-file listing, and non-ignored untracked-file listing were empty.
- **FACT** — The two commits initially ahead of cached `origin/master` were `32d1f03604a0274cb4aa68202d807e7e06265097` and `f69998f4c8ca13ef8e3313323da2d1f4341571df`. They were protected by the named local branch and were not endangered by switching.
- **FACT** — No local or remote tag matching `cct-modernization*` existed before tag creation.
- **FACT** — `origin` fetches from `git@github.com:GSA/piv-conformance.git` and pushes to `git@github-gsa:GSA/piv-conformance.git`.
- **FACT** — Fetch advanced `origin/master` to the expected merge commit and reported the merged `origin/feature/auto-package` branch deleted upstream.
- **FACT** — Local `master` was updated only by fast-forward from `62e8ebab…` to `be19a5c…`.
- **FACT** — Pre-existing ignored local files and generated build outputs were left untouched and are not part of this baseline inventory.

## 2. Environment

| Item | Observed value | Classification |
|---|---|---|
| OS | macOS 15.7.4, build 24G517; Darwin 24.6.0 | FACT |
| Architecture | `arm64` / Gradle reports `aarch64` | FACT |
| Java runtime | OpenJDK 11.0.32+0, Homebrew, 64-bit | FACT |
| Java compiler | `javac 11.0.32` | FACT |
| `JAVA_HOME` | Unset | FACT |
| `java` path | `/usr/bin/java` | FACT |
| `javac` path | `/usr/bin/javac` | FACT |
| Gradle JVM | `/opt/homebrew/Cellar/openjdk@11/11.0.32/libexec/openjdk.jdk/Contents/Home/bin/java` | FACT |
| Git | 2.50.1, Apple Git-155 | FACT |
| SQLite CLI | 3.43.2 | FACT |
| ZIP tooling | Apple Info-ZIP 3.0 / UnZip 6.00 | FACT |
| Docker | Client/Engine 29.7.2; Docker Desktop 4.90.0; Linux `arm64` engine available | FACT |
| WiX (`wix`, `candle`, `light`) | Not installed | FACT |
| PowerShell (`pwsh`, `powershell`) | Not installed | FACT |

### Gradle wrappers

| Module | Wrapper distribution | Runtime JVM | Result |
|---|---|---|---|
| `cardlib` | Gradle 6.6.1 | OpenJDK 11.0.32 | FACT — `./gradlew --no-daemon --version` succeeded |
| `conformancelib` | Gradle 6.6.1 | OpenJDK 11.0.32 | FACT — `./gradlew --no-daemon --version` succeeded |
| `tools/85b-swing-gui` | Gradle 6.6.1 | OpenJDK 11.0.32 | FACT — `./gradlew --no-daemon --version` succeeded |

- **FACT** — Each wrapper points to `https://services.gradle.org/distributions/gradle-6.6.1-bin.zip`.
- **FACT** — The three modules are independent Gradle roots; the repository root has no Gradle wrapper or settings file.

## 3. Repository / Module Inventory

### `cardlib`

- **FACT** — Core PIV card access and data-model library: PC/SC reader access, APDU transport, PIV application/card objects, TLV parsing, artifact writing, and utility runners.
- **FACT** — Contains 73 files under `src/main` and 13 Java test files under `src/test`.
- **FACT** — Tests include both fixture-backed data-object parsing and physical-reader/card operations.
- **FACT** — The build declares Java 11 source/target compatibility and produces `gov.gsa.pivconformance.cardlib-1.0.7.jar`.

### `conformancelib`

- **FACT** — Conformance orchestration library: SQLite-backed test definitions, JUnit discovery/listeners, SP 800-73/76/78 test atoms, validation, logging, and command-line support.
- **FACT** — Contains 72 files under `src/main` and no `src/test` directory.
- **FACT** — Its Gradle `test` source set points back to `src/main/java`; executable conformance atoms and `ValidatorTest` are therefore compiled as both production and test sources.
- **FACT** — It consumes the installed cardlib JAR from `../libs` and produces `gov.gsa.pivconformance.conformancelib-1.0.7.jar`.

### `tools/85b-swing-gui`

- **FACT** — Swing operator application for selecting a reader and SQLite profile, authenticating with the PIV application PIN, executing configured tests, viewing results, and packaging a completed run.
- **FACT** — Contains 44 files under `src/main` and two Java test files under `src/test`.
- **FACT** — It consumes cardlib and conformancelib through local flat-directory JAR resolution and produces `gov.gsa.pivconformance.gui-1.0.7-shadow.jar`.
- **FACT** — PR #326 added `CompletedTestRun`, `PackageResultsAction`, `ReviewPackageBuilder`, automatic post-run packaging, a manual “Package Results” action, selected-database path tracking, and lifecycle/package tests.

### Production profiles and test data

| Tracked SQLite profile | Total `TestCases` rows | Enabled rows | Classification |
|---|---:|---:|---|
| `PIV-I_ICAM_Test_Cards.db` | 489 | 274 | FACT |
| `PIV-I_Production_Cards.db` | 489 | 489 | FACT |
| `PIV_ICAM_Test_Cards.db` | 489 | 489 | FACT |
| `PIV_Production_Cards.db` | 489 | 489 | FACT |

- **FACT** — The four databases, corresponding SQL, XLSX inputs, schema, Python converter, and shell/batch database helpers live under `conformancelib/testdata`.
- **FACT** — SQLite `application_id` and `user_version` are both zero in all four databases; profile identity is primarily conveyed by the filename and database contents.

### Tracked helpers and documentation

- **FACT** — `doit.sh` sequentially builds/installs cardlib, conformancelib, and the Swing GUI, then assembles a timestamped application directory and ZIP.
- **FACT** — `tools/85b-swing-gui/ensuredeps.sh` runs `install` in the two libraries to populate local JAR dependencies.
- **FACT** — `tools/85b-swing-gui/make_zip.sh` is an older GUI packaging helper; `clean_stage.sh` rebuilds database staging content; `dumpcard.sh` invokes the container dump utility.
- **FACT** — Database generation helpers are `dump_db.sh`, `mk_db.sh`, `mk_db.bat`, `setup-venv.sh`, and `setup-venv.bat`.
- **FACT** — Relevant tracked documentation includes `README.md`, `docs/README.md`, `docs/HLD.md`, `cardlib/README.md`, test READMEs, historical build/test material, and coverage/reference artifacts under `docs`.
- **UNKNOWN** — No tracked CI workflow or formal release-automation definition exists at the baseline commit.

## 4. Existing Build Model

- **FACT** — Build order is cardlib → conformancelib → Swing GUI.
- **FACT** — Libraries are copied into the repository-local ignored `libs` directory, and later modules resolve them using `flatDir` repositories. This is file/order coupling rather than a single Gradle multi-project graph.
- **FACT** — The build uses Gradle 6.6.1, the retired JUnit Platform Gradle plugin 1.1.0 in cardlib/conformancelib, Shadow plugin 4.0.4, and extra-java-module-info plugin 0.1.
- **FACT** — Dependency repositories include JCenter, Maven Central, and Apache snapshot repositories.
- **FACT** — Declared baseline dependencies include JUnit Jupiter 5.7.0, Bouncy Castle 1.66, Logback 1.3.0-alpha5, SLF4J 2.0.0-alpha1, and SQLite JDBC 3.32.3.2 in cardlib versus 3.34.0 at conformancelib runtime.
- **FACT** — Each module reads version `1.0.7` from its own `src/main/resources/build.version`.
- **FACT** — Cardlib compilation generates an ignored `version.properties` containing the short Git commit, commit time, build time, and build version. The observed shaded JAR included `git.commit.id=be19a5c5` and `build.version=1.0.7`.
- **FACT** — The GUI shaded JAR manifest contains only `Manifest-Version: 1.0` and the GUI main class; it has no manifest implementation version or source commit.
- **FACT** — The tracked `doit.sh` distribution model creates `fips201-card-conformance-tool-<version>-<timestamp>.zip`, containing the shaded JAR, four databases, `pdval.properties`, `x509-certs`, logging configuration, `build.version`, and launch scripts.
- **OBSERVED RISK** — `docs/README.md` still instructs Java 8 setup even though the tracked Gradle properties target Java 11.
- **OBSERVED RISK** — Build-time source-resource generation and wall-clock timestamps make binary output sensitive to invocation time.
- **OBSERVED RISK** — Module-local wrappers and copied flat-directory JARs make success dependent on command order and stale ignored artifacts.

## 5. Test Baseline

The counts below are the numbers emitted by the current test runners. “Excluded” is not inferred when the runner did not expose it.

| Module / command path | Discovered | Executed | Passed | Failed | Skipped | Excluded | Overall | Classification |
|---|---:|---:|---:|---:|---:|---|---|---|
| cardlib normal `clean build install` / `clean test` | 14 | 14 | 6 | 8 | 0 | UNKNOWN | FAILED — 7 additional containers failed | FACT |
| conformancelib normal `clean build install` | 0 | 0 | 0 | 0 | 0 | 177 containers; 0 tests | FAILED — 1 container failed during setup | FACT |
| Swing GUI `clean test shadowJar` | 8 | 8 | 8 | 0 | 0 | 0 | PASSED | FACT |

### Exact PR #326 verification commands

- **FACT** — Cardlib `./gradlew --no-daemon clean install -x test -x junitPlatformTest -x generateHtmlTestReports` succeeded in 7 seconds. **BUILD PASSED WITH TESTS EXCLUDED.**
- **FACT** — Conformancelib `./gradlew --no-daemon clean install -x test -x junitPlatformTest` succeeded in 14 seconds. **BUILD PASSED WITH TESTS EXCLUDED.**
- **FACT** — Swing GUI `./gradlew --no-daemon clean test shadowJar` succeeded in 14 seconds with all 8 tests passing.
- **FACT** — The first two commands installed version 1.0.7 module JARs into the ignored `libs` directory; the GUI command generated the shaded JAR under `tools/85b-swing-gui/build/libs`.

## 6. Known Baseline Failures

- **TEST** — Seven cardlib parameterized-test containers failed with “You must configure at least one set of arguments.” The affected parsing suites declare `@ParameterizedTest` while their adjacent `@MethodSource` annotations are commented out.
- **ENVIRONMENT** — Eight cardlib tests failed with `IndexOutOfBoundsException` after directly indexing the empty terminal list. They were in `PIVConnectTests`, `PIVSignatureVerificationTests`, and `PIVGetDataTests` and require reader/card state not present on this host.
- **TEST** — The cardlib “Ensure readers” method uses the Java `assert` keyword; it was reported successful even though no reader was present, because the legacy JUnit Platform execution did not enable assertions for that process.
- **BUILD** — Conformancelib discovery reached `ValidatorTest` but setup failed because `pdval.properties`, `x509-certs/cacerts.jks`, and `x509-certs/valid/policy.xml` were sought relative to the module working directory. The tracked copies are under `src/main/resources`.
- **TEST** — Conformancelib reported 177 containers excluded by its `Sun` tag expression, then 0 tests found and one failed parameterized container. There is no trustworthy passing conformancelib test count in this baseline.
- **FIXTURE** — Cardlib cloned `https://github.com/GSA/gsa-icam-card-builder` branch `master` successfully into an ignored build directory on each clean legacy JUnit run; the acquisition is unpinned.
- **BUILD** — Gradle emitted illegal-reflective-access and Gradle-7-incompatibility/deprecation warnings.
- **UNKNOWN** — Hardware-dependent test outcomes with a compatible reader and representative PIV/PIV-I cards were not measured.

## 7. Hardware-Test Boundary

- **FACT** — macOS reports the CCID reader driver `fr.apdu.ccid.smartcardccid:1.5.1`.
- **FACT** — `system_profiler SPSmartCardsDataType` reported no readers and no available smart cards.
- **FACT** — `/usr/bin/pcsctest` is installed, but `SCardEstablishContext` returned `Service not available` in this session.
- **FACT** — No reader model or card identity can be recorded because no device was detected.
- **FACT** — Missing hardware is not counted as a successful hardware test.
- **UNKNOWN** — End-to-end physical-card behavior, test totals for each profile, PIN flow, reader/card swapping, and generated real-run packages remain unverified.

**HUMAN VERIFICATION REQUIRED**

1. Launch the packaged CCT from its distribution directory and record the exact JAR, OS, and Java version.
2. Select **Refresh Readers** and record the reader name/model shown by macOS and CCT.
3. Insert the intended non-production test card and record only whether CCT recognizes it; do not record a PIN or sensitive cardholder values.
4. Open and record the exact selected profile/database path and checksum.
5. Enter the test-card application PIN locally and select **Verify PIN and Execute Tests**; never include the PIN in evidence.
6. Record total, passed, failed, skipped, and unavailable result counts, then exercise **View Results**.
7. Confirm that completion automatically creates a `cct-results-*.zip` and record its safe filename/path and SHA-256.
8. Select **Package Results** and confirm a second package is created without overwriting the first.
9. Inspect the package only in approved local evidence storage; confirm its entries against Section 9 and keep any card-derived evidence out of Git.

## 8. Current GUI / Operator Workflow

- **FACT** — The GUI starts without opening a default test database; the operator opens a database through the File menu.
- **FACT** — The execution panel lists PC/SC readers, offers **Refresh Readers**, shows the selected database and reader status, accepts a PIV application PIN, and exposes **Verify PIN and Execute Tests**.
- **FACT** — At the end of a completed run, logs and extracted artifacts are timestamped, the latest run is captured with its selected database path, **View Results** and **Package Results** become visible, and packaging is invoked automatically.
- **FACT** — The manual **Package Results** action remains enabled for the latest completed run and creates another uniquely named ZIP.
- **FACT** — A successful package dialog offers **Show in Folder**, **Copy Path**, and **Close**.
- **FACT** — With no reader, code-level refresh produces an empty reader list and no card selection; attempts to execute continue into reader setup and display error dialogs rather than constituting a hardware pass.
- **UNKNOWN** — This GUI workflow was not launched through a physical reader/card in Phase 0.

## 9. Current Result Package Contract

### Naming, location, and selection

- **FACT** — Name: `cct-results-yyyyMMdd-HHmmss.zip`; if that path already exists, suffixes `-2`, `-3`, and so on are used.
- **FACT** — Location: the completed run’s results directory. The GUI supplies the process working directory (`user.dir`), so a normal packaged launch writes beside its runtime logs/resources.
- **FACT** — The selected SQLite database is included at the ZIP root under its basename. The canonical database path is captured when the database is opened.
- **FACT** — Entry names are sorted lexicographically before ZIP creation.
- **FACT** — Existing packages and files unrelated to the run prefix are not included.

### Included evidence

- **FACT** — Prefix-matching regular files are collected recursively from `logs`, `piv-artifacts`, and `x509-artifacts`.
- **FACT** — `logs` is mandatory and the selected run must produce exactly one prefix-matching CSV anywhere below it.
- **FACT** — `piv-artifacts` and `x509-artifacts` are optional; they are included when present and populated for the selected prefix.
- **FACT** — `x509-certs` is mandatory and every regular trust-material file under it is included without the run-prefix filter.
- **FACT** — Source evidence bytes are copied unchanged.
- **OBSERVED RISK** — Real run entry names can contain a FASC-N or GUID-derived identifier because the timestamp prefix is formed from captured card identifiers. Packages must be handled as potentially sensitive evidence.

### Representative synthetic package

The existing production package builder was invoked twice against non-sensitive synthetic inputs. The first ZIP contained:

| Entry | Size (bytes) | Classification |
|---|---:|---|
| `PIV_Production_Cards.db` | 18 | FACT — synthetic placeholder |
| `logs/apdu/synthetic-card_20260911_100000-20260911_100100-apdu_transmission.log` | 21 | FACT — synthetic placeholder |
| `logs/conformancelog/synthetic-card_20260911_100000-20260911_100100-conformance_results.csv` | 81 | FACT — synthetic placeholder |
| `piv-artifacts/synthetic-card_20260911_100000-20260911_100100-chuid.bin` | 3 | FACT — synthetic placeholder |
| `x509-artifacts/synthetic-card_20260911_100000-20260911_100100-authentication.crt` | 21 | FACT — synthetic placeholder |
| `x509-certs/cacerts.jks` | 21 | FACT — synthetic placeholder |
| `x509-certs/valid/policy.xml` | 12 | FACT — synthetic placeholder |

- **FACT** — ZIP 1: `cct-results-20260911-103136.zip`, 1,628 bytes, SHA-256 `43501922061dc45cad371992f559e7dedc6bf9023f1692a0d19540d23efc3c10`.
- **FACT** — ZIP 2: `cct-results-20260911-103139.zip`, SHA-256 `4aec6def9b9996e6ea040102ee573c980a116a132b533328062451a659e64924`.
- **FACT** — Both archives had the same seven entries, sizes, CRCs, and concatenated payload SHA-256 `7e82a3c5849e5d866a2ed0ea45979e3529ab8405497dbe6640c217b6d8183a31`.
- **FACT** — The ZIPs were not byte-for-byte identical. Entry timestamps were package-construction time (`10:31:36` versus `10:31:38`), producing different whole-archive hashes for equivalent inputs.
- **FACT** — No manifest exists inside the result ZIP.
- **FACT** — No internal artifact hashes or checksum file exist inside the result ZIP.
- **FACT** — No CCT build version, Git commit, Java/runtime identity, or package format version exists inside the result ZIP.
- **FACT** — The selected database filename is the only package-level profile hint; no explicit standards revision or profile metadata exists.

## 10. Known Non-Determinism / Reproducibility Risks

- **OBSERVED RISK** — Cardlib clones the mutable `master` branch of `GSA/gsa-icam-card-builder` during `junitPlatformTest`; no commit is pinned or recorded in the result.
- **OBSERVED RISK** — JCenter and Apache snapshot repositories are configured, and no dependency lock or verification metadata was found.
- **OBSERVED RISK** — Clean test behavior depends on network access and the changing contents/layout of a remote repository.
- **OBSERVED RISK** — Tests and runtime validation assume files relative to `user.dir`, causing behavior to change with launch directory.
- **OBSERVED RISK** — The cardlib-generated `version.properties` embeds wall-clock build time.
- **OBSERVED RISK** — Result package names and every ZIP entry timestamp embed wall-clock time; equivalent inputs do not produce an identical ZIP checksum.
- **OBSERVED RISK** — Profile databases are generated from XLSX through local Python/SQLite helper scripts without a single captured toolchain definition.
- **OBSERVED RISK** — PC/SC and physical-card state affect both test discovery/execution and outcomes.
- **UNKNOWN** — Reproducibility on Windows x64, Intel macOS, and a host with active PC/SC hardware was not measured.

## 11. Current Build / Dependency Risks

### P0 — blocks a trustworthy modernization comparison

- **OBSERVED RISK** — The normal cardlib and conformancelib paths fail on this clean baseline, so later work must compare against the recorded failure signatures rather than treating green builds with exclusions as equivalent.
- **OBSERVED RISK** — Mutable fixture acquisition and working-directory resource assumptions prevent a hermetic, repeatable test baseline.

### P1 — should be addressed during modernization

- **OBSERVED RISK** — Gradle 6.6.1, JUnit Platform plugin 1.1.0, Shadow 4.0.4, JCenter, snapshot resolution, alpha logging dependencies, and mixed SQLite JDBC versions are aging or unstable build inputs.
- **OBSERVED RISK** — Physical-card coverage has no automated substitute in this environment and still requires a controlled human run.
- **OBSERVED RISK** — Result ZIPs omit manifest, internal hashes, build identity, format version, and explicit standards/profile identity.
- **OBSERVED RISK** — Local flat-directory JAR installation creates cross-module order and stale-artifact coupling.

### P2 — cleanup / improvement

- **OBSERVED RISK** — Build/run documentation is inconsistent with the tracked Java target.
- **OBSERVED RISK** — Legacy packaging and staging helpers use relative paths and destructive shell operations, making operator context significant.
- **OBSERVED RISK** — The GUI application JAR manifest does not expose the build version or commit even though a shaded resource does.

## 12. Baseline Artifacts

- **FACT** — Generated shaded JAR: `tools/85b-swing-gui/build/libs/gov.gsa.pivconformance.gui-1.0.7-shadow.jar`.
- **FACT** — JAR size: 20,194,710 bytes.
- **FACT** — JAR SHA-256 after the final exact PR #326 command sequence: `a308a373225ffe5afbc92ba46469b30951f3c13893e1e4ac569d7b7166cf74bd`.
- **FACT** — Local-only evidence root: `/private/tmp/cct-baseline-evidence-2026-09-11`.
- **FACT** — Preserved normal-path logs: `cardlib-normal-build.log`, `cardlib-clean-test.log`, `conformancelib-normal-build.log`, and `swing-gui-clean-test-shadowjar.log`.
- **FACT** — Preserved textually exact PR #326 command logs: `cardlib-pr326-exact.log`, `conformancelib-pr326-exact.log`, and `swing-gui-pr326-exact.log`.
- **FACT** — Synthetic package evidence is under `/private/tmp/cct-baseline-evidence-2026-09-11/synthetic-package-fixture`.
- **FACT** — The evidence root is outside the repository; it is not tracked and contains no real card, PIN, private-key, or cardholder evidence created by this phase.
- **FACT** — Generated Gradle outputs and installed local JARs are ignored by Git.
- **UNKNOWN** — No representative physical-card result package was generated because no reader/card was available.

## 13. Human Verification Still Required

- **UNKNOWN** — Reader recognition and model reporting.
- **UNKNOWN** — Card recognition and safe PIN verification.
- **UNKNOWN** — Full PIV and PIV-I production-profile totals and outcomes.
- **UNKNOWN** — Result viewing after a physical-card run.
- **UNKNOWN** — Automatic and manual result-package creation from a physical-card run.
- **UNKNOWN** — Real package location, filename, checksum, warnings, and errors.

Use the controlled checklist in Section 7. Do not commit the resulting package or any extracted PIV/card evidence.

## 14. Explicit Phase-0 Non-Changes

- **FACT** — This phase made no intentional change to CCT conformance behavior.
- **FACT** — This phase made no intentional change to NIST test expectations.
- **FACT** — This phase made no intentional change to the Java version.
- **FACT** — This phase made no intentional change to the Gradle version.
- **FACT** — This phase made no intentional change to application dependencies.
- **FACT** — This phase made no intentional change to GUI behavior.
- **FACT** — This phase made no intentional change to result semantics.
- **FACT** — This phase made no intentional change to packaging behavior.
- **FACT** — This phase made no intentional change to database contents.
- **FACT** — No production source, test source, Gradle file, or generated/sensitive evidence is an intended repository change; only this baseline document is intended for review.
