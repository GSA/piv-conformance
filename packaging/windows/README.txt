CCT {{VERSION}} for Windows x64

1. Extract the entire ZIP using Extract All.
2. Open the extracted folder and double-click CCT.exe.

Java is included. You do not need to install Java or change PATH.
Keep CCT.exe, app and runtime together; CCT.exe is a launcher, not an installer.
A compatible card reader and any required drivers or middleware are still needed.

Choose PIV or PIV-I for the production card type. Use File > Open Database
for an ICAM test profile or another approved database. Select the reader,
enter the card's PIV application PIN and click Verify PIN and Execute Tests.
Use View Test Results to review the run, then Package Results to save it.

USER_GUIDE.md covers profiles, Results, submission and diagnostics.
Logs and results are stored under %LOCALAPPDATA%\GSA\CCT.
Existing per-user trust files are preserved on upgrade.

BUILD-INFO.txt records the source commit and bundled runtime.
The runtime's licenses and notices are retained under runtime/legal.
For download verification, compare the ZIP's SHA-256 with the published value.
This package is for Windows x64. Developers and other platforms can use the
portable Java-required package or build the source with a Java 17 JDK.
