#!/usr/bin/env bash

usage ()
{
    echo ""
    echo "Generate Certificate Signing Request"
    echo ""
    echo "$(basename $0) [CONFIG] [PRIVATE_KEY] [CSR]"
    echo ""
    echo "TODO use options..."
    echo ""
}

if [ $# -lt 3 ]; then
    echo "$(basename $0): Too few arguments"
    usage
    exit 1
fi

if [ $# -gt 3 ]; then
    echo "$(basename $0): Too many arguments"
    usage
    exit 1
fi

CONFIG="$1"
PRIVATE_KEY="$2"
CSR="$3"

if [ -z $CONFIG ]; then
    echo "$(basename $0): Invalid CONFIG"
    exit 1
fi
if [ -z $PRIVATE_KEY ]; then
    echo "$(basename $0): Invalid PRIVATE_KEY"
    exit 1
fi
if [ -z $CSR ]; then
    echo "$(basename $0): Invalid CSR"
    exit 1
fi

openssl req \
    -new \
    -config $CONFIG \
    -keyout $PRIVATE_KEY \
    -out $CSR
