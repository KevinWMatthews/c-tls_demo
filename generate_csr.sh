#!/usr/bin/env bash

usage ()
{
    echo ""
    echo "$(basename $0) [CONFIG] [PRIVATE_KEY] [CSR]"
    echo ""
    echo "Generate Certificate Signing Request"
    echo ""
    echo "Create a CSR from a config file and private key."
    echo ""
    echo "Options:"
    echo "  CONFIG          Configuration for openssl req for the new certificate"
    echo "  PRIVATE_KEY     Existing private key file for the new certificate/key pair"
    echo "  CSR             Name of resulting CSR"
    echo "  --prefix        Optional path prefix for config, key, and csr. TODO Finish this!"
    echo ""
    echo "It is possible to create both a key and CSR with a single same call. For simplicity, this script does not allow this."
    echo "It is possible to create a CSR from an existing CSR. For simplicity, this script does not allow this."
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
    -key $PRIVATE_KEY \
    -out $CSR
