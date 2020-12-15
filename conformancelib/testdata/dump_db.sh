#!/bin/bash


SQLITE=${SQLITE:-$(which sqlite3)}

die () {
    echo "$@" >&2
    exit 1
}

if [[ ! -x ${SQLITE} ]]; then
    die "No executable sqlite3 command could be found"
fi

DBFILE=$1

if [[ -z ${DBFILE} ]]; then
    die "No database file specified"
fi

OUTFILE=${OUTFILE:-${DBFILE}.sql}

if [[ -f ${OUTFILE} ]]; then
    die "${OUTFILE} already exists. Specify a different file or move it."
fi

${SQLITE} ${DBFILE} <<EOCMD
.output ${OUTFILE}
.dump
.quit
EOCMD

if [[ $? != 0 ]]; then
    die "Dump command failed."
fi

echo "Finished dumping ${DBFILE} to ${OUTFILE}"
exit 0
