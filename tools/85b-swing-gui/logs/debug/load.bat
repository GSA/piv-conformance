
@ECHO off
::  Script to import and trust CACERTS entries into the JSSECACERTS file
::  run this file from a Java servers home directory with no arguments
::------
SETLOCAL EnableDelayedExpansion
SET fileobject=jars\myServer.jar
if defined J_HOME (
  GOTO JREHOMESET
)
SET "dir=%~f0"
:LOOP
CALL :GETDIR "%dir%"
IF EXIST "%dir%\%fileobject%" (
  ECHO Found J_HOME at %dir%\
  GOTO :HOMESET
)
IF "%dir:~-1%" == ":" (
  ECHO Reached root and directory containing "%fileobject%" not found.
  GOTO :end
)
GOTO :LOOP
:HOMESET
SET J_HOME=%dir%\
:JREHOMESET
if not defined JAVA_HOME (
  SET JAVA_HOME=!J_HOME!Javasoft\jre
)
echo Set JAVA_HOME to %JAVA_HOME%
::------
:: trust any self signed public keys that are contained in keystores located in cacerts directory
if exist cacerts (
  for /F "tokens=1 delims=." %%i in ('dir /b cacerts') do (
    %JAVA_HOME%\bin\keytool.exe -importkeystore -destkeystore jssecacerts -deststoretype jks -srcstorepass changeit -deststorepass changeit -v -srcalias tomcat -noprompt -destalias %%i -srckeystore cacerts\%%i.keystore
  )
)
::------
:: then, trust some of the CA certs from the JRE default cacerts file
%JAVA_HOME%\bin\keytool.exe -importkeystore -destkeystore jssecacerts -deststoretype jks -srcstorepass changeit -deststorepass changeit -v -noprompt -srckeystore %JAVA_HOME%\lib\security\cacerts
ECHO.
::------
:: create the file trustedJSSEcerts.txt
ECHO Determine trusted CAs of the candidate jssecacerts for the JRE
%JAVA_HOME%\bin\keytool.exe -list -keystore jssecacerts -storepass changeit >> trustedCAsTEMP.txt
ECHO. 2>trustedJSSEcacerts.txt  
FOR /F "tokens=2,4*" %%i IN (trustedCAsTEMP.txt) DO (
  IF "%%i" == "fingerprint" (
    ECHO %%j >> trustedJSSEcacerts.txt
  )
)
SORT trustedJSSEcacerts.txt /OUTPUT trustedJSSEcerts.txt
DEL /Q trustedCAsTEMP.txt
:: the file trustedJSSEcacerts.txt is a unsorted temp file that can also be deleted
DEL /Q trustedJSSEcacerts.txt
::------
:testexist
if exist %JAVA_HOME%\lib\security\trustedJSSEcerts.txt (
  ECHO The file %JAVA_HOME%\lib\security\trustedJSSEcerts.txt already exists.
  GOTO compare
) else (
  XCOPY trustedJSSEcerts.txt %JAVA_HOME%\lib\security\ /y /d >nul
  ECHO Copied a new trustedJSSEcerts.txt into %JAVA_HOME%\lib\security for first time.
  GOTO nodiff
)
:compare
if exist %JAVA_HOME%\lib\security\trustedJSSEcerts.txt (
  ECHO Comparing candidate keystore signatures with JRE jssecacerts keystore
  fc trustedJSSEcerts.txt %JAVA_HOME%\lib\security\trustedJSSEcerts.txt > nul
  if errorlevel 1 GOTO nodiff
)
ECHO.
::------
GOTO diff
:GETDIR
SET "dir=%~dp1"
SET "dir=%dir:~0,-1%"
EXIT /B 0
::-------
:diff
ECHO File compare detected no differences. Since certs are not new, will not update jssecacerts in JRE.
GOTO end
::------
:nodiff
XCOPY jssecacerts %JAVA_HOME%\lib\security\ /y /d >nul
ECHO Copied updated jssecacerts into JRE because file was newer than the previous version.
::------
:end
pause