#!/bin/bash

# Default to always test with Gradle

TESTOPT=1
if [ "$1" == "-notest" ]; then
  TESTOPT=0
fi

pushd cardlib >/dev/null 2>&1
    ./gradlew -stop
    ./gradlew --refresh-dependencies
    if [ $TESTOPT -eq 1 ]; then
        ./gradlew clean
        ./gradlew build install installSource
    else
        ./gradlew clean
        ./gradlew -x junitPlatformTest -x generateHtmlTestReports clean install installSource
    fi
    ./gradlew -stop
popd >/dev/null 2>&1

pushd conformancelib >/dev/null 2>&1
    ./gradlew -stop
    ./gradlew --refresh-dependencies
    if [ $TESTOPT -eq 1 ]; then
        ./gradlew clean
        ./gradlew build install installSource
    else
        ./gradlew -x test clean install installSource
    fi    
    ./gradlew -stop
popd >/dev/null 2>&1

pushd tools/85b-swing-gui 2>&1
    ./gradlew -stop
    ./gradlew --refresh-dependencies
    ./gradlew clean
    ./gradlew -x test clean build install installSource
    cp build/libs/*shadow* ../../libs
    ./gradlew -stop
popd >/dev/null 2>&1

set -x
VERSION=$(cat ./tools/85b-swing-gui/build/resources/main/build.version)
rm -rf fips201-card-conformance-tool-$VERSION
mkdir -p fips201-card-conformance-tool-$VERSION
pushd fips201-card-conformance-tool-$VERSION >/dev/null 2>&1
    cp -p ../conformancelib/testdata/*.db .
    cp -p ../cardlib/build/resources/main/user_log_config.xml .
    cp -p ../tools/85b-swing-gui/build/resources/main/build.version .
    tar xvf ../tools/85b-swing-gui/build/distributions/gov.gsa.pivconformance.gui-shadow-$VERSION.tar
    mv gov.gsa.pivconformance.gui-shadow-$VERSION/lib/gov.gsa.pivconformance.gui-$VERSION-shadow.jar .
    touch directly-asserted.flag
    rm -rf gov.gsa.pivconformance.gui-shadow-$VERSION
    echo "java -Djava.security.debug=certpath,provider -jar $(ls *-shadow.jar) >console.log 2>&1\r" >run.bat
    echo "java -Djava.security.debug=certpath,provider -jar $(ls *-shadow.jar) >console.log 2>&1" >run.sh
popd

TS=$(date +%Y%m%d%H%M%S)
mv fips201-card-conformance-tool-$VERSION fips201-card-conformance-tool-${VERSION}-${TS}
zip fips201-card-conformance-tool-${VERSION}-${TS}.zip fips201-card-conformance-tool-${VERSION}-${TS}/*
