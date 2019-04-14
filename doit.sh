#!/usr/bin/bash
pushd cardlib >/dev/null 2>&1
	./gradlew clean
	./gradlew eclipse
	./gradlew install
popd >/dev/null 2>&1

pushd conformancelib >/dev/null 2>&1
	./gradlew clean
	./gradlew eclipse
	./gradlew shadowJar
popd >/dev/null 2>&1

pushd tools/85b-swing-gui 2>&1
	./ensuredeps.sh
	./gradlew clean
	./gradlew eclipse
	./gradlew shadowJar
popd >/dev/null 2>&1
