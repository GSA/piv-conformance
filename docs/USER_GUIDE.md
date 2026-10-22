# CCT user guide

These instructions describe the Java 17 **1.1.0 release candidate**, including its Testing and Results tabs. Use the instructions supplied with your downloaded version. The release's wiki pages retain guidance for older releases.

- [Running the Card Conformance Tool](#running-the-card-conformance-tool)
- [Viewing Test Results](#viewing-test-results)
- [Submit Test Results](#submit-test-results)
- [Diagnostics](#diagnostics)

## Running the Card Conformance Tool

### Choose the download

On the [releases page](https://github.com/GSA/piv-conformance/releases), download the versioned **piv-conformance ZIP** and its `.sha256` file to run CCT. This package contains the built application, launchers, four test databases, configuration, trust files and instructions. Java 17 is installed separately.

**Source code (zip)** and **Source code (tar.gz)** contain the repository's source at the release tag. They are equivalent source snapshots in different archive formats, intended for developers and source review. They require a build before use. GitHub generates these two archives automatically; public downloads do not require a GitHub account. See [GitHub's release documentation](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases).

### Verify, extract and start

1. Compare the ZIP's SHA-256 with both the release page and its `.sha256` file. In Windows PowerShell, use `Get-FileHash "<zip-file>" -Algorithm SHA256`; on macOS, `shasum -a 256 "<zip-file>"`; on Linux, `sha256sum "<zip-file>"`.
2. Extract the entire ZIP. Keep the JAR, launchers, databases, configuration and `x509-certs` directory together. Read `README.txt` for version-specific instructions.
3. Install Java 17. In the launch terminal, check that `java -version` reports Java 17. The launchers use `java` on `PATH`; setting `JAVA_HOME` alone does not change that selection.
4. On Windows, open `run.bat` from the extracted folder. On macOS/Linux, run `./run.sh` from a terminal in that folder. If needed, select Java 17 for that invocation with `PATH="/path/to/jdk-17/bin:$PATH" ./run.sh`.

You also need a compatible card reader, its required platform drivers/middleware and the card's PIV application PIN. Check the release notes for tested operating systems and hardware.

### Select the profile

For an ordinary card evaluation, choose **PIV** or **PIV-I** on the toolbar according to the card type designated by its issuer or evaluation lab. These open the corresponding production database. Check **Test Database** before running.

| Database | Use |
|---|---|
| `PIV_Production_Cards.db` | Production PIV cards; selected by **PIV**. |
| `PIV-I_Production_Cards.db` | Production PIV-I cards; selected by **PIV-I**. |
| `PIV_ICAM_Test_Cards.db` | Known ICAM PIV test cards when instructed. |
| `PIV-I_ICAM_Test_Cards.db` | Known ICAM PIV-I test cards when instructed. |

Use **File → Open Database** to select another supplied or approved custom `.db` file. ICAM test profiles include expected negative results; use the profile intended for the card under test.

### Connect and run

1. Connect the reader and insert the card.
2. Click **Refresh Readers**, choose the reader under **Card Reader**, and check **Reader Status**. If the reader is absent, check its connection and platform setup, then refresh again.
3. Enter the correct **PIV Application PIN**. Click **Verify PIN and Execute Tests**. Follow the progress in the test tree. Follow the issuer's recovery procedure for a blocked PIN.
4. When results have been finalized, choose **View Test Results**. CCT also attempts to package the run automatically; **Package Results** lets you create another copy later in the same session.

### Output locations and upgrades

CCT writes run data separately from the extracted application:

| Platform | Default data directory |
|---|---|
| Windows | `%LOCALAPPDATA%\GSA\CCT` (normally under the user's `AppData\Local`) |
| macOS | `~/Library/Application Support/GSA/CCT` |
| Linux | `$XDG_DATA_HOME/GSA/CCT`, or `~/.local/share/GSA/CCT` when unset |

Result ZIPs are saved under `runs/` in that directory. Logs, card artifacts, extracted certificates and trust material are described under [Diagnostics](#diagnostics). A configured `cct.data.dir` overrides the default.

An existing per-user `x509-certs/cacerts.jks` is preserved on upgrade. Review its approved trust anchors and intermediates with your PKI administrator. Back up customized files before an intentional replacement; extracting a newer application does not replace an existing per-user trust store.

## Viewing Test Results

**View Test Results** opens the native **Results** tab inside CCT. The tab appears after a run produces a result snapshot. Use **Testing** or **Back to Testing** to return to the card workflow.

The header identifies the run's database, completion time and duration. The small footer shows the application version. Four cards show **Cases processed**, **Pass**, **Fail** and **Unsupported**. These are case outcomes, not standards-coverage percentages or a card-certification decision.

### Find cases needing attention

The initial **Needs attention** view includes failed or unsupported cases and results that differ from the profile's expected outcome. Click a summary card or use the filter to select an outcome; **All cases** includes passing cases. Optional search narrows by case ID, description, object or recorded reason.

| Actual result | Meaning |
|---|---|
| **Pass** | The case completed without a recorded assertion failure. Optional-absence paths can also complete without evaluating a field. |
| **Fail** | An assertion failed or an execution problem occurred. Read the recorded cause and profile expectation. |
| **Unsupported** | CCT has no implemented assertion for the case or cannot establish it with the available evidence. This does not by itself mean card data is missing. |

The current tests have no separate Warning or Caution verdict. A negative ICAM test may expect **Fail**; its actual result remains **Fail**, with that expectation shown separately.

### Read a finding

Select a case to see its description, object and expected/actual outcome. Detailed findings include the recorded reason and expected/observed values where supplied by the test.

Reviewed source cards distinguish **Official wording (excerpt)** from **What CCT checks**. They identify the publication, edition and section/table, with a link to the cited PDF page or document section where available. The explanation describes the check's scope; a short quotation does not establish coverage of every requirement in the publication. Some legacy or custom steps still have no reviewed source binding and are identified explicitly.

The captured explanation and excerpts remain available offline. Opening the official source requires a connection and a suitable browser. **Technical evidence** expands the recorded step and diagnostic trace. **Open run debug log** opens the matching log; **Copy finding** copies the finding and its reviewed sources. Passing cases have a compact detail view.

**Open CSV** opens the run's original CSV in the default associated application. It is also saved under `logs/conformancelog/` in the data directory, with the run's identifier/timestamps in the filename. Compare its Expected Result and Actual Result columns; retain the CSV as original evidence.

### Another run or an interrupted run

Starting a new run clears the prior Results view; the new snapshot replaces it when finalized. Switching between Testing and Results preserves the current snapshot. A run that stops early and can be finalized is marked **Incomplete**; review its execution message and available logs. Force-quitting the application may prevent finalization and packaging.

The native view is for the current session. After restarting CCT, use the saved CSV, logs and packaged text summary to review earlier runs.

## Submit Test Results

### Create the CCT package

Use **Package Results** from Testing or Results for the finalized run. The completion panel offers **Show in Folder**, **Copy Path**, **View Results** and **Done**.

The ZIP contains the selected test database, matching-run files under `logs`, `piv-artifacts` and `x509-artifacts` when produced, and the `x509-certs` directory. It includes one conformance CSV and a UTF-8 `*-results-summary.txt` with counts and detailed findings/sources. The summary is included even when Results was never opened. Trust material is included as a directory; retain the package as generated so reviewers have its validation context.

### Prepare the lab submission

The CCT ZIP is one part of the submission. Follow the [GSA FIPS 201 Evaluation Program](https://www.idmanagement.gov/fips201ep/) and [FPKI submission instructions](https://www.idmanagement.gov/fpki/#submitting-a-test-results-package) for the applicable evaluation. Those instructions also call for:

- A signed [testing application](https://www.idmanagement.gov/docs/fips201ep-pcitestform.pdf) for each PCI configuration evaluated.
- The card's Answer-to-Reset (ATR), available through **Reader Status** when the card is read.
- Certificate-profile reports for the card's certificates. Use the current [GSA Certificate Profile Conformance Tool distribution](https://github.com/GSA/cpct-tool/releases) and its instructions.
- High-resolution front and back card photographs, plus any additional artifacts required for the chosen lab process.

Use the lab's current submission channel; its published contact is `fips201ep@gsa.gov`. Follow the lab's directions for transmitting card information. CCT's **Package Results** action creates a local ZIP; it does not submit it. Zipping only the application installation directory omits this version's per-user run data.

## Diagnostics

Start with the selected Results finding. Compare the profile expectation, actual result, recorded reason and cited requirement before examining the lower-level files.

| Location under the data directory | Contents/use |
|---|---|
| `logs/debug/` | Combined diagnostics, assertion failures and execution exceptions. **Open run debug log** selects the matching run. |
| `logs/conformancelog/` | Conformance CSV and readable results summary. |
| `logs/testlog/` | Test progress and case execution messages. |
| `logs/containers/` | Decoded container/tag diagnostics. |
| `logs/apdu/` | Card command/response transmission diagnostics. |
| `piv-artifacts/` | Binary card-object evidence. |
| `x509-artifacts/` | Extracted X.509 certificates, when available. |
| `x509-certs/` | Validation trust material and certificates saved during path building. |

Match the run identifier/timestamps before comparing files. Search the debug log for the case ID and executed method; use the technical evidence to distinguish an assertion failure from a reader, acquisition, setup or software error. An execution error alone does not establish a card-data violation.

CCT retains SP 800-85B-derived case IDs. Additional numbering levels are CCT subdivisions; they are not current NIST clause numbers. Follow the executed method, object and profile to the applicable source. Historical PIV-I references must not be replaced automatically with PIV requirements.

The selected modernization baseline is [FIPS 201-3](https://csrc.nist.gov/pubs/fips/201-3/final), [SP 800-73-5 Part 1](https://csrc.nist.gov/pubs/sp/800/73/pt1/5/final), [SP 800-78-5](https://csrc.nist.gov/pubs/sp/800/78/5/final) and [SP 800-76-2](https://csrc.nist.gov/pubs/sp/800/76/2/final). A passing CCT run proves neither complete coverage of those publications nor certification of the card.

For certificate path errors, review the recorded cause, certificate validity, intended policies and approved trust material, including preserved per-user files. An extracted end-entity certificate may be available even when a path cannot be built. Resolve a trust configuration problem through the approved PKI process.

The packaged `user_log_config.xml` configures **Logback through SLF4J**. Preserve its `${LOG_DIR}` paths when changing logging, and restart CCT to apply configuration changes. The older wiki's Log4j configuration instructions and installation-directory output paths describe earlier releases.
