#!/usr/bin/env bash

usage ()
{
    echo ""
    echo "$(basename $0) [CONFIG] [PRIVATE_KEY] [CSR]"
    echo ""
    echo "Generate Certificate Signing Request and Private Key"
    echo ""
    echo "This script creates a private key and a CSR."
    echo "It is possible to create a CSR from an existing CSR."
    echo "For simplicity, this script does not allow this."
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

# Could generate private key separately using 'openssl genrsa'
openssl req \
    -new \
    -config $CONFIG \
    -keyout $PRIVATE_KEY \
    -out $CSR
