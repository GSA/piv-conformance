#!/bin/bash
#
# A simple script to make sure the install targets have been run on the two local library components
#  (chiefly necessary because buildship is not behaving well with multi-project gradle builds, and
#  this was the most expedient workaround)

# adapted from a couple of the answers here:
# https://stackoverflow.com/questions/59895/get-the-source-directory-of-a-bash-script-from-within-the-script-itself
SCRIPT_SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SCRIPT_SOURCE" ]; do
  SCRIPT_DIR="$( cd -P "$( dirname "$SCRIPT_SOURCE" )" >/dev/null 2>&1 && pwd )"
  SCRIPT_SOURCE="$(readlink "$SCRIPT_SOURCE")"
  [[ $SCRIPT_SOURCE != /* ]] && SCRIPT_SOURCE="$SCRIPT_DIR/$SCRIPT_SOURCE"
done
SCRIPT_DIR="$( cd -P "$( dirname "$SCRIPT_SOURCE" )" >/dev/null 2>&1 && pwd )"

CARDLIB=${SCRIPT_DIR}/../../cardlib
CONFORMANCELIB=${SCRIPT_DIR}/../../conformancelib

if [[ ! -d ${CARDLIB} || ! -d ${CONFORMANCELIB} ]]; then
    echo "This sript needs to live within the piv-conformance tree."
    echo "${CARDLIB} must exist."
    echo "${CONFORMANCELIB} must exist."
    exit 1
fi

# halt on any errors after this
set -e

pushd ${CARDLIB}
./gradlew install
popd
pushd ${CONFORMANCELIB}
./gradlew install
popd

