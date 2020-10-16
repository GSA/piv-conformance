#!/bin/bash

pushd cardlib >/dev/null 2>&1
	./gradlew -x junitPlatformTest -x generateHtmlTestReports clean build install
popd >/dev/null 2>&1

pushd conformancelib >/dev/null 2>&1
	./gradlew -x test clean build install
popd >/dev/null 2>&1

pushd tools/85b-swing-gui 2>&1
	./gradlew -x test clean build
	cp build/libs/*shadow* ../../libs
popd >/dev/null 2>&1

VERSION=$(cat ./tools/85b-swing-gui/build/resources/main/build.version)
rm -rf fips201-card-conformance-tool-$VERSION
mkdir -p fips201-card-conformance-tool-$VERSION
pushd fips201-card-conformance-tool-$VERSION >/dev/null 2>&1
	cp -p ../conformancelib/testdata/*.db .
	cp -p ../tools/85b-swing-gui/build/resources/main/user_log_config.xml .
	cp -p ../tools/85b-swing-gui/build/resources/main/build.version .
	tar xvf ../tools/85b-swing-gui/build/distributions/gov.gsa.pivconformance.gui-shadow-$VERSION.tar
	mv gov.gsa.pivconformance.gui-shadow-$VERSION/lib/gov.gsa.pivconformance.gui-$VERSION-shadow.jar .
popd
