#!/usr/bin/bash
pushd cardlib >/dev/null 2>&1
		set -x
       ./gradlew clean
       ./gradlew install
		set +x
popd >/dev/null 2>&1

pushd conformancelib >/dev/null 2>&1
		set -x
       ./gradlew clean
       ./gradlew shadowJar
		set +x
popd >/dev/null 2>&1

#pushd tools/85b-swing-gui 2>&1
#		set -x
#       ./gradlew clean
#       ./gradlew jar
#		set +x
#popd >/dev/null 2>&1

