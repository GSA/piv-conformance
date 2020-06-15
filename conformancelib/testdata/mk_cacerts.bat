@ECHO off

echo Set JAVA_HOME to %JAVA_HOME%

if exist cacerts (
	cd cacerts
	"%JAVA_HOME%\bin\keytool.exe" -importcert -destkeystore cacerts.keystore -deststoretype jks -deststorepass changeit -v -noprompt -file fcpca.crt
	COPY cacerts.keystore ..\..\tools\85b-swing-gui
	cd ..
)

pause