#!/bin/bash

JAVA=${JAVA:-$(which java)}
CCT_JAR=${CCT_JAR:-build/libs/85b-swing-gui-all.jar}

if [[ ! -x ${JAVA} ]];then
    echo "No java executable could be found. Either ensure that it is on the path or set the JAVA environment variable."
    exit 1
fi

if [[ ! -f ${CCT_JAR} ]];then
    echo "The card conformance jar could not be found. Use the CCT_JAR environment variable to specify it."
    exit 1
fi

OUTDIR=${OUTDIR:-$(pwd)/dump.$(date +'%Y%m%d%H%M%S')}

mkdir -p ${OUTDIR}

if [[ ! -d ${OUTDIR} ]];then
    echo "${OUTDIR} does not exist and could not be created."
    exit 1
fi

${JAVA} -cp ${CCT_JAR} gov.gsa.conformancelib.pivconformancetools.ContainerDump -o ${OUTDIR} -l


