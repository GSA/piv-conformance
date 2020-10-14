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

