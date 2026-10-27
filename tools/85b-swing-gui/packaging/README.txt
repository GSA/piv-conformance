CCT __CCT_VERSION__ portable application (Java 17 required)

Full running, Results, submission and diagnostics instructions are in the
included USER_GUIDE.md. Download the versioned piv-conformance ZIP to run CCT;
GitHub's Source code ZIP and tar.gz require a build. Public downloads do not
require a GitHub account.

Extract the whole ZIP before running CCT. Keep the JAR, four databases,
configuration files and x509-certs directory together. For optional SHA-256
verification, see "Verify the download" in USER_GUIDE.md.

Install Java 17 and check java -version in the launch terminal. The scripts use
java on PATH; JAVA_HOME alone does not select it. Windows: double-click run.bat.
macOS/Linux: run ./run.sh from a terminal. If another Java is the default, run
PATH="/path/to/jdk-17/bin:$PATH" ./run.sh using your Java 17 installation path.

Choose PIV or PIV-I in the toolbar, or File > Open Database for another .db
profile. Insert the card, click Refresh Readers, select its reader, and check
Reader Status. Enter the PIV application PIN in the GUI and click Verify PIN
and Execute Tests. After completion, use View Test Results to open the Results
tab inside CCT. It appears after a run and updates for each new run. Use the
summary cards, filters and sorting to find a case. Details show its reason,
expected outcome and available source references. Official excerpts and CCT
explanations are labeled separately; source links open online.

Results use the same Pass, Fail and Unsupported labels as the CSV. Unsupported
means a check is not implemented or needs evidence CCT does not have. It does
not by itself mean card data is missing. The supplied profiles expect Pass;
an ICAM label does not automatically make a failure expected. Execution errors
also retain the Fail label. See USER_GUIDE.md for details.

Package Results works from Testing or Results. Its ZIP includes the selected
database, matching logs and artifacts, x509-certs, and a readable results summary,
even if Results was never opened. The completion dialog offers Show in Folder,
Copy Path, View Results and Done.

Logs and packages are written under the per-user GSA/CCT data directory:
Windows: %LOCALAPPDATA%\GSA\CCT
macOS: ~/Library/Application Support/GSA/CCT
Linux: $XDG_DATA_HOME/GSA/CCT, or ~/.local/share/GSA/CCT when XDG_DATA_HOME is unset
Package Results writes its ZIP under the data directory's runs folder.

An existing per-user x509-certs/cacerts.jks is preserved. Before using a new
trust bundle, have your operator review any customized copy in the GSA/CCT
data directory. Back it up before replacing it with the one in this ZIP.

This release updates selected checks for FIPS 201-3, SP 800-73-5 Part 1 and
SP 800-78-5; it also corrects selected checks under unchanged SP 800-76-2.
It is not a complete standards-conformance or card-certification claim. Some
cases report Unsupported when required external evidence is unavailable.
