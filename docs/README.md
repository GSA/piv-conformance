# CCT documentation

The [user guide](USER_GUIDE.md) covers running CCT, the native Results page, preparing a lab submission and diagnostics. The [root README](../README.md) provides a quick start and the scope of the selected standards updates.

## Building with Java 17

The active GUI build uses the three existing modules in order: `cardlib`, `conformancelib`, then `tools/85b-swing-gui`. Use a Java 17 JDK, set `JAVA_HOME`, and put its `bin` directory on `PATH`. Gradle wrappers download the specified Gradle distribution and dependencies on the first build.

From the repository root, use the [build sequence](../README.md#build-status). For the tested flat-ZIP recipe, run `./doit.sh` in a Bash environment with `zip` and `shasum` available. It runs the software checks and writes the runnable ZIP and checksum under `build/releases/`. Building that ZIP on Windows requires those shell tools; running an extracted ZIP on Windows uses `run.bat`.

For module builds from Windows PowerShell, start at the repository root with Java 17 selected:

```powershell
Push-Location .\cardlib
.\gradlew.bat check install
if ($LASTEXITCODE -ne 0) { throw "Cardlib build failed." }
Pop-Location
Push-Location .\conformancelib
.\gradlew.bat check install
if ($LASTEXITCODE -ne 0) { throw "Conformancelib build failed." }
Pop-Location
Push-Location .\tools\85b-swing-gui
.\gradlew.bat test shadowJar
if ($LASTEXITCODE -ne 0) { throw "GUI build failed." }
Pop-Location
```

The GUI Shadow JAR is written under `tools/85b-swing-gui/build/libs/`. A JAR alone is not the complete release package.

### Windows package with Java included

Build this package on **Windows x64** using PowerShell. The packaging script downloads and selects its pinned Java 17 JDK for this build; it does not change the system Java installation. From the repository root:

```powershell
.\packaging\windows\package-windows.ps1 -SmokeTest
```

The script downloads Amazon Corretto 17.0.21.0.11 over HTTPS and verifies its pinned SHA-256. It builds and checks the three modules, creates a runtime image with every vendor Java module, and creates a native `CCT.exe` launcher with `jpackage --type app-image`. The image omits development archives, debug information, headers and manuals while preserving module licenses and vendor notices. It checks the module inventory and security files against the vendor archive, including the roots named in [OpenJDK's CA-compromise guidance](https://openjdk.org/emudhra). The ZIP and checksum are written to a new folder under `build/releases/`. Existing output is not overwritten.

The launcher and application window use the existing GSA artwork in the GUI's `icons` resources. `gsa.ico` provides Windows icon sizes from 16 to 256 pixels, derived from `exelogo.png` for small sizes and `gsa_logo.png` for larger sizes. Update it alongside those PNGs if the artwork changes.

`-SmokeTest` runs the original-row regressions under both providers using the extracted package's runtime, opens all four databases and checks the native window without Java on `PATH`. A compatible card/reader run is still required. `-SkipBuild` packages an already checked build; it is intended for maintainers, not clients.

The Windows workflow builds QA artifacts only. It does not create tags, publish releases or upload release assets. Record the source commit and runtime in `BUILD-INFO.txt`; keep the exact accepted ZIP for publication. Recheck the pinned runtime's security status at release freeze and update its version, URL, hash and release-file checks together when needed. The same pinned JDK supplies compilation, packaging and the private runtime. Update that runtime by distributing a new CCT package.

The ZIP includes an executable launcher, not an MSI installer. Confirm supported Windows architectures, signing/allowlisting requirements and runtime maintenance ownership with the release team before publication. Keep the portable Java-required ZIP and both source archive formats available. Source archives support development; they are not a ready-to-run fallback.

### Building a source archive

GitHub's Source code ZIP and tar.gz contain the same tagged source and omit Git history. Cardlib's version-generation task normally reads the commit ID and timestamp from Git. When building an extracted source archive, supply the matching values recorded in the release notes:

```sh
export CCT_GIT_COMMIT="<source commit SHA from the release notes>"
export CCT_GIT_COMMIT_EPOCH="<commit Unix timestamp from the release notes>"
./doit.sh
```

In PowerShell, set `$env:CCT_GIT_COMMIT` and `$env:CCT_GIT_COMMIT_EPOCH` before the module build sequence. These variables provide version metadata; they do not replace Java 17, Gradle dependencies or the shell tools needed by `doit.sh`. Release maintainers must verify a build from the exact source archives before publication.

## JUnit tests

CCT's profile workbooks, SQL and SQLite databases select existing JUnit test methods (atoms), card containers and parameters. Conformancelib performs the assertions; Cardlib acquires/decodes data, and the GUI records results. Original SP 800-85B-derived case IDs remain in use. See [How the checks are organized](../README.md#how-the-checks-are-organized).

`conformancelib`'s `check` task includes the original-row regressions under SUN and Bouncy Castle. These use controlled acquisition fixtures; they do not replace an extracted-package card/PIN run. The separate `certificateFixtureTest` task requires the external historical certificate fixture set and is not evidence supplied by the ordinary build.

The previous Java 8/Eclipse build instructions are historical. Use the documentation at the corresponding older source tag when maintaining an older release.
