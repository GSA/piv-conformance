# Building the PIV Conformance Tool

## Dependencies
JDK >= 11

## Updating the version
When the version of the tool needs to be updated, update the "revision" field inside "properties" in the parent pom.xml file in the root directory of the project.

## Build command
from the top directory of the project (the directory with this file)

### Linux/Unix/MacOS

`./mvnw package -f pom.xml`

### Windows (Powershell)
`.\mvnw.cmd -f pom.xml`