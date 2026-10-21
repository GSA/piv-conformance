CCT __CCT_VERSION__ release candidate

Compare the ZIP's SHA-256 with its .sha256 file and the release page. Use
Get-FileHash "<zip-file>" -Algorithm SHA256 in Windows PowerShell,
shasum -a 256 "<zip-file>" on macOS, or sha256sum "<zip-file>" on Linux.
Extract the whole ZIP before running CCT. Keep the JAR, four databases,
configuration files and x509-certs directory together.

Install Java 17 and check java -version in the launch terminal. The scripts use
java on PATH; JAVA_HOME alone does not select it. Windows: double-click run.bat.
macOS/Linux: run ./run.sh from a terminal. If another Java is the default, run
PATH="/path/to/jdk-17/bin:$PATH" ./run.sh using your Java 17 installation path.

Choose PIV or PIV-I in the toolbar, or File > Open Database for another .db
profile. Insert the card, click Refresh Readers, select its reader, and check
Reader Status. Enter the PIV application PIN in the GUI and click Verify PIN
and Execute Tests. After completion, use View Test Results to open the Results
tab inside CCT. It appears after a run produces results and refreshes for each
new run. The Testing tab returns to the existing card workflow. Select a summary
card or filter by outcome to inspect recorded reasons and available references.
The result labels are Pass, Fail and Unsupported, matching the CSV. Profile
expectations and execution errors are explained separately in case details.
Optional search narrows by case number, object or reason. The version is at the
lower right.

Package Results creates a ZIP for that run from either Testing or Results.
The results ZIP includes the selected database, the completed run's logs and
artifacts, x509-certs, and a readable *-results-summary.txt containing counts
and case details requiring review.
It is included even if Results was never opened. The completion dialog offers
Show in Folder, Copy Path, View Results and Done.
Unsupported can mean an unimplemented CCT check or unavailable external
evidence (such as vendor values or original input images). It is not a passing
result and does not by itself mean card data is missing. The view identifies
steps without a recorded source reference.

Logs and packages are written under the per-user GSA/CCT data directory:
Windows: %LOCALAPPDATA%\GSA\CCT
macOS: ~/Library/Application Support/GSA/CCT
Linux: $XDG_DATA_HOME/GSA/CCT, or ~/.local/share/GSA/CCT when XDG_DATA_HOME is unset
Package Results writes its ZIP under the data directory's runs folder.

An existing per-user x509-certs/cacerts.jks is preserved. Before using a new
trust bundle, have your operator review any customized copy in the GSA/CCT
data directory. Back it up before replacing it with the one in this ZIP.

This candidate updates selected checks for FIPS 201-3, SP 800-73-5 Part 1 and
SP 800-78-5; it also corrects selected checks under unchanged SP 800-76-2.
It is not a complete standards-conformance or card-certification claim. Some
cases report Unsupported when required external evidence is unavailable.
