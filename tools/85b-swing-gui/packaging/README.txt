CCT __CCT_VERSION__ release candidate

Extract the whole ZIP before running CCT. Keep the JAR, databases and x509-certs
directory together. Install Java 17 if it is not already available on PATH.

Windows: double-click run.bat. macOS/Linux: run ./run.sh from a terminal.
Select the PIV or PIV-I profile in the toolbar, choose a card reader, then run
the tests. Use View Results for the report and Package Results to create a ZIP.
Unsupported means the card read did not establish that case's requirement; it
is not a passing result.

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
