#!/bin/bash

SYMBOLIZE=`which symbolize`
if [ -n "${SYMBOLIZE}" ]; then
    echo 'The symbolize command already exists'
    exit 0
fi

LOCAL_BIN="/usr/local/bin"
if [ ! -d "${LOCAL_BIN}" ]; then
    mkdir -p "${LOCAL_BIN}"
fi

SCRIPT_PATH=$(cd `dirname $0`; pwd)
cp "${SCRIPT_PATH}/symbolize.py" "${LOCAL_BIN}/symbolize"
chmod u+x "${LOCAL_BIN}/symbolize"
