#!/bin/bash

bash ./ensuredeps.sh
./gradlew shadowJar
if [[ -d 85b-swing-gui ]]; then
    echo "!!! warning: existing 85b-swing-gui directory is in the way."
    echo "!!! to clean up, run the following commands then re-run this script"
    for f in $(find 85b-swing-gui -type f -print); do
        echo "/bin/rm ${f}"
    done
fi
mkdir -p 85b-swing-gui
cp ./build/libs/85b-swing-gui-all.jar 85b-swing-gui
cp -i ./user_log_config.xml 85b-swing-gui/
zip -r 85b-swing-gui-$(date +'%Y%m%d').zip 85b-swing-gui

