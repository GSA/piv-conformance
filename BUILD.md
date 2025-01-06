# Building the PIV Conformance Tool

## Dependencies
JDK >= 11

## Updating the version
When the version of the tool needs to be updated, update the "revision" field inside "properties" in the parent pom.xml file in the root directory of the project. Also update the `/piv-conformance/gui/src/main/resources/build.version` which is read by the gui to display the version number in the titlebar of the main application window. Make sure both version numbers match to keep both synced. 

## Build command
from the top directory of the project (the directory with this files) run `./doit.sh`

### Linux/Unix/MacOS
Run the following command in the main directory containing the project's pom file. 
`./mvnw package -f pom.xml`

### Windows (Powershell)
Run the following command in the main directory containing the project's pom file. 
`.\mvnw.cmd -f pom.xml`

### Run the program
After the program builds successfully, from the main directory execute `run.sh` or `run.bat`. If you are running a release version, the build process is not needed, simply run the `run.sh` or `run.bat`.