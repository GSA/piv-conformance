#!/bin/bash

bash ./ensuredeps.sh
./gradlew shadowJar

DESTDIR=${DESTDIR:-fips201-cct}
STAMP=$(date +'%Y%m%d%H%M')

if [[ -d ${DESTDIR} ]]; then
    echo "!!! warning: existing $DESTDIR directory is in the way."
    echo "!!! to clean up, run the following commands then re-run this script"
    for f in $(find $DESTDIR -type f -print); do
        echo "/bin/rm ${f}"
    done
fi
mkdir -p $DESTDIR
cp ./build/libs/FIPS-201-Card-Conformance-Tool.jar $DESTDIR/
cp -i ./user_log_config.xml $DESTDIR/
[[ -z $CLEANLOGS ]] && rm $DESTDIR/*.log $DESTDIR/*.csv $DESTDIR/*.csv.html
cp -i ../../conformancelib/testdata/PIV*Cards.db $DESTDIR/
[[ -z $DONTZIP ]] && zip -r FIPS-201-Card-Conformance-Tool-$STAMP.zip $DESTDIR
echo "FIPS-201-Card-Conformance-Tool-$STAMP.zip"

