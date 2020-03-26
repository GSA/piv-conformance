#!/bin/bash
. ./tools/85b-swing-gui/ensuredeps.sh

pushd cardlib >/dev/null 2>&1
	./gradlew --warning-mode=all clean
	./gradlew --warning-mode=all eclipse
	./gradlew --warning-mode=all installSource
	./gradlew --warning-mode=all install
popd >/dev/null 2>&1

pushd conformancelib >/dev/null 2>&1
	./gradlew --warning-mode=all clean
	./gradlew --warning-mode=all eclipse
	./gradlew --warning-mode=all shadowJar
popd >/dev/null 2>&1

pushd tools/85b-swing-gui 2>&1
	./ensuredeps.sh
	./gradlew --warning-mode=all clean
	./gradlew --warning-mode=all eclipse
	./gradlew --warning-mode=all shadowJar
popd >/dev/null 2>&1
