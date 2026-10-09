#!/usr/bin/env bash

set -euo pipefail

run_tests=1
if [[ "${1:-}" == "-notest" ]]; then
    run_tests=0
fi

build_module() {
    local module_directory="$1"
    shift
    pushd "$module_directory" >/dev/null
    ./gradlew --no-daemon "$@"
    popd >/dev/null
}

if [[ $run_tests -eq 1 ]]; then
    build_module cardlib clean build install installSource
    build_module conformancelib clean build install installSource
    build_module tools/85b-swing-gui clean build install installSource
else
    build_module cardlib clean install installSource -x test
    build_module conformancelib clean install installSource -x test
    build_module tools/85b-swing-gui clean install installSource -x test
fi

version="$(tr -d '[:space:]' < tools/85b-swing-gui/src/main/resources/build.version)"
if [[ -z "$version" || ! "$version" =~ ^[0-9A-Za-z._-]+$ ]]; then
    echo "Invalid build version: $version" >&2
    exit 1
fi

timestamp="$(date +%Y%m%d%H%M%S)"
package_name="fips201-card-conformance-tool-${version}-${timestamp}"
staging_directory="fips201-card-conformance-tool-${version}"
application_jar="tools/85b-swing-gui/build/libs/gov.gsa.pivconformance.gui-${version}-shadow.jar"

if [[ ! -f "$application_jar" ]]; then
    echo "Missing application jar: $application_jar" >&2
    exit 1
fi

rm -rf -- "$staging_directory"
mkdir -p "$staging_directory"
cp -p cardlib/build/resources/main/user_log_config.xml "$staging_directory/"
cp -p conformancelib/testdata/*.db "$staging_directory/"
cp -p conformancelib/src/main/resources/pdval.properties "$staging_directory/"
cp -pr conformancelib/src/main/resources/x509-certs "$staging_directory/"
cp -p tools/85b-swing-gui/build/resources/main/build.version "$staging_directory/"
cp -p "$application_jar" "$staging_directory/"

jar_name="$(basename "$application_jar")"
printf 'java -Djava.security.debug=certpath -jar "%s" >>console.log 2>&1\r\n' "$jar_name" > "$staging_directory/run.bat"
printf '#!/usr/bin/env sh\njava -Djava.security.debug=certpath -jar "%s" >>console.log 2>&1\n' "$jar_name" > "$staging_directory/run.sh"
chmod 755 "$staging_directory/run.sh"

mv "$staging_directory" "$package_name"
zip -r "${package_name}.zip" "$package_name"
