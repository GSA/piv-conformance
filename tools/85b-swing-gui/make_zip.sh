#!/bin/bash

bash ./ensuredeps.sh
./gradlew shadowJar

DESTDIR=${DESTDIR:-85b-swing-gui}
STAMP=$(date +'%Y%m%d%H%M')

if [[ -d ${DESTDIR} ]]; then
    echo "!!! warning: existing $DESTDIR directory is in the way."
    echo "!!! to clean up, run the following commands then re-run this script"
    for f in $(find $DESTDIR -type f -print); do
        echo "/bin/rm ${f}"
    done
fi
mkdir -p $DESTDIR
cp ./build/libs/85b-swing-gui-all.jar $DESTDIR/
cp -i ./user_log_config.xml $DESTDIR/
[[ -z $CLEANLOGS ]] && rm $DESTDIR/*.log $DESTDIR/*.csv $DESTDIR/*.csv.html
#cp -i ../../conformancelib/testdata/85b_test_definitions_PIV_ICAM_Test_Cards.db $DESTDIR/
[[ -z $DONTZIP ]] && zip -r 85b-swing-gui-$STAMP.zip $DESTDIR
echo "File to upload: 85b-swing-gui-$STAMP.zip"

