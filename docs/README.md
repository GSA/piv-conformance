# CCT documentation

The [user guide](USER_GUIDE.md) covers running CCT, the native Results page, preparing a lab submission and diagnostics. The [root README](../README.md) provides a quick start and the scope of the selected standards updates.

## Building with Java 17

The active GUI build uses the three existing modules in order: `cardlib`, `conformancelib`, then `tools/85b-swing-gui`. Use a Java 17 JDK, set `JAVA_HOME`, and put its `bin` directory on `PATH`. Gradle wrappers download the specified Gradle distribution and dependencies on the first build.

From the repository root, use the [build sequence](../README.md#build-status). For the tested flat-ZIP recipe, run `./doit.sh` in a Bash environment with `zip` and `shasum` available. It runs the software checks and writes the runnable ZIP and checksum under `build/releases/`. Building that ZIP on Windows requires those shell tools; running an extracted ZIP on Windows uses `run.bat`.

For module builds from Windows PowerShell, use each module's `gradlew.bat` in place of `./gradlew`, preserving the same module/task order. The GUI Shadow JAR is written under `tools/85b-swing-gui/build/libs/`. A JAR alone is not the complete release package.

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
