#!/bin/sh
set -eu

data_dir=${CCT_DATA_DIR:-/data}
mkdir -p "$data_dir"
cp -Rn /opt/cct/bootstrap/. "$data_dir/"
cd "$data_dir"

exec java -jar /opt/cct/cct.jar "$@"
