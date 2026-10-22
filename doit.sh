#!/usr/bin/env bash

# Build and package the GUI using the same flat ZIP layout as the published CCT.
set -euo pipefail

if [[ $# -ne 0 ]]; then
    echo "Usage: ./doit.sh" >&2
    exit 2
fi

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$repo_root"

if [[ -z "${JAVA_HOME:-}" || ! -x "$JAVA_HOME/bin/javac" \
        || "$("$JAVA_HOME/bin/javac" -version 2>&1)" != javac\ 17.* ]]; then
    echo "Set JAVA_HOME to a Java 17 JDK before building CCT." >&2
    exit 1
fi
for command_name in zip shasum; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "Required packaging command is missing: $command_name" >&2
        exit 1
    fi
done

version="$(tr -d '[:space:]' < tools/85b-swing-gui/src/main/resources/build.version)"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-rc[0-9]+)?$ ]]; then
    echo "Invalid CCT version: $version" >&2
    exit 1
fi
for module in cardlib conformancelib; do
    module_version="$(tr -d '[:space:]' < "$module/src/main/resources/build.version")"
    if [[ "$module_version" != "$version" ]]; then
        echo "$module version $module_version does not match GUI version $version" >&2
        exit 1
    fi
done

expected_jks_hash="41496e64cb241c8f98bebee33ff2f1f98530d4febc2ab0b9d369910578628a10"
jks_path="conformancelib/src/main/resources/x509-certs/cacerts.jks"
actual_jks_hash="$(shasum -a 256 "$jks_path" | cut -d ' ' -f 1)"
if [[ "$actual_jks_hash" != "$expected_jks_hash" ]]; then
    echo "Trust store differs from the verified v1.0.9 release asset: $jks_path" >&2
    exit 1
fi

build_module() {
    local module="$1"
    shift
    (cd "$module" && ./gradlew --no-daemon clean "$@")
}

build_module cardlib check install
build_module conformancelib check install
build_module tools/85b-swing-gui test shadowJar

jar_name="gov.gsa.pivconformance.gui-${version}-shadow.jar"
jar_path="tools/85b-swing-gui/build/libs/$jar_name"
if [[ ! -f "$jar_path" ]]; then
    echo "Missing GUI Shadow JAR: $jar_path" >&2
    exit 1
fi

output_dir="$repo_root/build/releases"
mkdir -p "$output_dir"
stage="$(mktemp -d "$output_dir/.cct-stage.XXXXXX")"
archive="$output_dir/piv-conformance-${version}-$(date -u +%Y%m%dT%H%M%SZ).zip"
trap 'rm -rf -- "$stage"' EXIT

cp "$jar_path" "$stage/"
cp cardlib/src/main/resources/user_log_config.xml "$stage/"
cp conformancelib/src/main/resources/pdval.properties "$stage/"
cp tools/85b-swing-gui/src/main/resources/build.version "$stage/"
for profile in PIV_ICAM_Test_Cards PIV_Production_Cards PIV-I_ICAM_Test_Cards PIV-I_Production_Cards; do
    cp "conformancelib/testdata/${profile}.db" "$stage/"
done
mkdir -p "$stage/x509-certs/valid"
cp "$jks_path" "$stage/x509-certs/cacerts.jks"
cp conformancelib/src/main/resources/x509-certs/valid/policy.xml "$stage/x509-certs/valid/"
cp conformancelib/src/main/resources/x509-certs/valid/valid.zip "$stage/x509-certs/valid/"
sed "s/__CCT_VERSION__/$version/g" tools/85b-swing-gui/packaging/README.txt > "$stage/README.txt"
cp docs/USER_GUIDE.md "$stage/USER_GUIDE.md"
sed "s/__CCT_JAR__/$jar_name/g" tools/85b-swing-gui/packaging/run.bat \
    | awk '{ sub(/\r$/, ""); printf "%s\r\n", $0 }' > "$stage/run.bat"
sed "s/__CCT_JAR__/$jar_name/g" tools/85b-swing-gui/packaging/run.sh > "$stage/run.sh"
chmod 755 "$stage/run.sh"

(cd "$stage" && zip -q -X -r "$archive" *)
echo "Created $archive"
(cd "$output_dir" && shasum -a 256 "$(basename "$archive")" > "$(basename "$archive").sha256")
cat "$archive.sha256"
