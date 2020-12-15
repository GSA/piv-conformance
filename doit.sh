#!/bin/bash

# Default to always test with Gradle

TESTOPT=1
if [ "$1" == "-notest" ]; then
  TESTOPT=0
fi

GRADLE=$(type gradle 2>/dev/null | awk '{ print $3 }')
if [ ! -z "$GRADLE" ]; then gradle -stop; fi

pushd cardlib >/dev/null 2>&1
    ./gradlew clean
    if [ $TESTOPT -eq 1 ]; then
        ./gradlew build install installSource || exit 1 
    else
        ./gradlew -x junitPlatformTest -x generateHtmlTestReports clean install installSource || exit 1
    fi
popd >/dev/null 2>&1

pushd conformancelib >/dev/null 2>&1
    ./gradlew clean
    if [ $TESTOPT -eq 1 ]; then
        ./gradlew build install installSource || exit 1
    else
        ./gradlew -x test clean install installSource || exit 1
    fi    
popd >/dev/null 2>&1

pushd tools/85b-swing-gui 2>&1
    ./gradlew clean
    ./gradlew -x test clean build install installSource || exit 1
    cp build/libs/*shadow* ../../libs
popd >/dev/null 2>&1

VERSION=$(cat ./tools/85b-swing-gui/build/resources/main/build.version)
rm -rf fips201-card-conformance-tool-$VERSION
mkdir -p fips201-card-conformance-tool-$VERSION
pushd fips201-card-conformance-tool-$VERSION >/dev/null 2>&1
    cp -p ../conformancelib/testdata/*.db .
    cp -p ../cardlib/build/resources/main/user_log_config.xml .
    cp -p ../tools/85b-swing-gui/build/resources/main/build.version .
    tar xvf ../tools/85b-swing-gui/build/distributions/gov.gsa.pivconformance.gui-shadow-$VERSION.tar
    cp -p gov.gsa.pivconformance.gui-shadow-$VERSION/lib/gov.gsa.pivconformance.gui-$VERSION-shadow.jar .
    touch directly-asserted.flag
    rm -rf gov.gsa.pivconformance.gui-shadow-$VERSION
    echo "java -Djava.security.debug=certpath,provider -jar $(ls *-shadow.jar) >console.log 2>&1\r" >run.bat
    echo "java -Djava.security.debug=certpath,provider -jar $(ls *-shadow.jar) >console.log 2>&1" >run.sh
    chmod 755 run.sh
popd

TS=$(date +%Y%m%d%H%M%S)
mv fips201-card-conformance-tool-$VERSION fips201-card-conformance-tool-${VERSION}-${TS}
zip fips201-card-conformance-tool-${VERSION}-${TS}.zip fips201-card-conformance-tool-${VERSION}-${TS}/*
