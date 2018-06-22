#!/usr/bin/env bash

usage ()
{
    echo ""
    echo "$(basename $0) [CONFIG] [PRIVATE_KEY] [CERT]"
    echo ""
    echo "Generate self-signed certificate and private key"
    echo ""
}

CONFIG="$1"
PRIVATE_KEY="$2"
CERT="$3"

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
if [ -z $CERT ]; then
    echo "$(basename $0): Invalid CERT"
    usage
    exit 1
fi

# Generate private key and cert in one command
# Could generate private key separately using 'openssl genersa'
openssl req \
    -new \
    -x509 \
    -nodes \
    -days 1095 \
    -inform PEM \
    -outform PEM \
    -config $CONFIG \
    -keyout $PRIVATE_KEY \
    -out $CERT
