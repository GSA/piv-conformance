#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"

if ! command -v java >/dev/null 2>&1; then
    echo "CCT requires Java 17 on PATH." >&2
    exit 1
fi
java_spec="$(java -XshowSettings:properties -version 2>&1 | sed -n 's/^[[:space:]]*java.specification.version = //p' | head -n 1)"
if [ "$java_spec" != 17 ]; then
    echo "CCT requires Java 17 on PATH (found ${java_spec:-unknown})." >&2
    exit 1
fi
exec java -Dcct.packaged=true -jar "__CCT_JAR__"
