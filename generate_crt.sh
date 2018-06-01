#!/usr/bin/env bash

usage ()
{
    echo ""
    echo "Generate self-signed certificate and private key"
    echo ""
    echo "$(basename $0) [CONFIG] [PRIVATE_KEY] [CRT]"
    echo ""
}

CONFIG="$1"
PRIVATE_KEY="$2"
CRT="$3"

if [ -z $CONFIG ]; then
    echo "$(basename $0): Invalid CONFIG"
    usage
    exit 1
fi
if [ -z $PRIVATE_KEY ]; then
    echo "$(basename $0): Invalid PRIVATE_KEY"
    usage
    exit 1
fi
if [ -z $CRT ]; then
    echo "$(basename $0): Invalid CRT"
    usage
    exit 1
fi


openssl req \
    -new \
    -x509 \
    -days 1095 \
    -config $CONFIG \
    -keyout $PRIVATE_KEY \
    -out $CRT
