@echo off
setlocal
pushd "%~dp0"
if errorlevel 1 goto directory_error

if not defined LOCALAPPDATA set "LOCALAPPDATA=%USERPROFILE%\AppData\Local"
set "CCT_DATA_DIR=%LOCALAPPDATA%\GSA\CCT"
if not exist "%CCT_DATA_DIR%" mkdir "%CCT_DATA_DIR%"
if not exist "%CCT_DATA_DIR%\." goto data_error

where java >nul 2>&1
if errorlevel 1 goto java_error
set "JAVA_SPEC="
for /f "tokens=2 delims==" %%V in ('java -XshowSettings:properties -version 2^>^&1 ^| findstr /c:"java.specification.version ="') do set "JAVA_SPEC=%%V"
set "JAVA_SPEC=%JAVA_SPEC: =%"
if not "%JAVA_SPEC%"=="17" goto java_error

java "-Dcct.packaged=true" "-Dcct.data.dir=%CCT_DATA_DIR%" -jar "__CCT_JAR__" >> "%CCT_DATA_DIR%\console.log" 2>&1
set "CCT_EXIT=%ERRORLEVEL%"
if "%CCT_EXIT%"=="0" exit /b 0
echo CCT exited with error %CCT_EXIT%. See "%CCT_DATA_DIR%\console.log".
pause
exit /b %CCT_EXIT%

:java_error
echo CCT requires Java 17 on PATH. Install a Java 17 runtime and try again.
pause
exit /b 1

:data_error
echo Cannot create the CCT data directory: "%CCT_DATA_DIR%".
pause
exit /b 1

:directory_error
echo Cannot open the extracted CCT directory.
pause
exit /b 1
