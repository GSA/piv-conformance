#!/bin/bash
VERSION=$(cat ./gui/src/main/resources/build.version)
# Timestamp of build
TS=$(date +%Y%m%d%H%M%S)

# Clean Option
if [ "$1" == "-cleanup" ]; then
    echo ""
    echo "Cleaning up /piv-conformance directory."
    echo ""
    echo "one moment..."
    echo ""
    ./mvnw clean
    echo ""
    echo "Clean-up is complete, run ./doit.sh to build piv-conformance again."
    exit
fi


# Run Script Setup: 
#
### Populates run script file for Linux, GitBash, WSL, or Macs (rewritten each run of doit.sh and captures version/release number.)
echo "java -Djava.security.debug=certpath -jar gui/target/gui-$VERSION.jar >>console.log 2>&1" > run.sh

### Populates run script file for Windows (rewritten each run of doit.sh and captures version/release number.)
echo "java -Djava.security.debug=certpath -jar gui\\target\\gui-$VERSION.jar >>console.log 2>&1\r" > run.bat

# OSTYPE
echo ""
echo "You are running on $OSTYPE"
echo ""

### Running install process...
echo ""
echo "Running the build process for CCT Tool $VERSION..."
echo ""
./mvnw package -f pom.xml
echo ""
echo "The build process is complete"
echo "Execute the run.sh or run.bat file to run piv-conformance."
