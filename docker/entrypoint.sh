#!/bin/sh
set -eu

cp -Rn /opt/cct/bootstrap/. /data/
exec java -jar /opt/cct/cct.jar "$@"
