# Windows portable distribution

CCT's Windows release is a Java 17 `jpackage` application image. It uses the
existing shaded JAR because that is the smallest reliable class-path input: all
third-party Java dependencies and service descriptors are already assembled in
one tested file. `jpackage` creates `CCT.exe` and a trimmed private runtime, so
the destination computer does not need Java, Gradle, Git, Docker, or an IDE.

Windows application images are platform-specific. Build this artifact on
64-bit Windows with a Windows x64 Java 17 JDK:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-windows.ps1
```

The script verifies the JDK, uses the checked-in Gradle wrappers, performs clean
builds and all hardware-free tests, builds the shaded JAR, runs `jpackage`,
validates the image, creates the ZIP, and emits its SHA-256 file. The outputs are:

```text
dist/
  fips201-card-conformance-tool-<version>-windows-x64.zip
  fips201-card-conformance-tool-<version>-windows-x64.zip.sha256
```

The ZIP expands to this structure (implementation-detail runtime files omitted):

```text
fips201-card-conformance-tool-<version>-windows-x64/
  CCT.exe
  START_HERE.txt
  BUILD-INFO.txt
  app/
    CCT.cfg
    cct.jar
    build.version
    user_log_config.xml
    pdval.properties
    x509-certs/
    PIV_Production_Cards.db
    PIV-I_Production_Cards.db
    PIV_ICAM_Test_Cards.db
    PIV-I_ICAM_Test_Cards.db
  runtime/
```

At runtime, installed resources are read from `app`. Working files are written
under `%LOCALAPPDATA%\GSA\CCT`, including `logs`, `piv-artifacts`,
`x509-artifacts`, and uniquely named `runs\cct-results-*.zip` files. Validation defaults
are copied there on first launch so downloaded certificate-path material also
stays writable. Resource precedence is: an explicit working-directory copy,
the per-user copy, the packaged resource, and finally the bundled class-path
copy.

## Fresh Windows acceptance test

Use a Windows 10 or Windows 11 x64 computer or VM that does not have Java
installed. Save screenshots or notes for each observation.

1. Verify `java -version` is not available before extracting CCT.
2. Verify the published ZIP against its `.zip.sha256` file.
3. Extract the complete ZIP to a normal user-writable folder.
4. Double-click `CCT.exe`; do not launch it from inside the ZIP.
5. Confirm the Swing CCT window opens and reports the expected version.
6. Use the two default database buttons and File > Open Database to confirm all
   four databases can be selected and their test trees load.
7. Confirm the GUI remains usable and reader enumeration behaves sensibly both
   with no reader and, if available, with a supported reader attached.
8. Confirm `%LOCALAPPDATA%\GSA\CCT` exists and is writable. Confirm logs appear
   there rather than beneath the extracted application image.
9. Close the application normally, relaunch `CCT.exe`, and confirm it opens again.
10. If an approved card and reader are available, run one specifically approved
    non-destructive smoke test. Confirm its logs and result ZIP are created under
    `%LOCALAPPDATA%\GSA\CCT`. Do not run state-changing tests for this check.

Do not claim the release is Windows-verified until this checklist passes on the
fresh machine. A source archive can be used instead of a Git checkout for a
manual build. CI can check out the source on a Windows runner, install a Windows
x64 Java 17 JDK, run the same script, and publish the two files from `dist`.
