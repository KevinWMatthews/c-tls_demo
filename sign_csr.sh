#!/usr/bin/env bash

#https://www.sslshopper.com/article-most-common-openssl-commands.html
#https://www.shellhacks.com/decode-csr/

usage ()
{
    echo ""
    echo "Sign a Certificate Signing Request using a Certifate Authority's self-signed certificate"
    echo ""
    echo "$(basename $0) [CONFIG] [CA_KEY] [CSR] [CRT]"
    echo ""
    echo "Read config, input a CSR, sign with the CA's private PEM, output a CRT"
}

if [ $# -lt 4 ]; then
    echo "$(basename $0): Too few arguments"
    usage
    exit 1
fi

if [ $# -gt 4 ]; then
    echo "$(basename $0): Too many arguments"
    usage
    exit 1
fi

CONFIG="$1"
CA_KEY="$2"
CSR="$3"
CRT="$4"

if [ -z $CONFIG ]; then
    echo "$(basename $0): Invalid CONFIG"
    exit 1
fi
if [ -z $CA_KEY ]; then
    echo "$(basename $0): Invalid CA_KEY"
    exit 1
fi
if [ -z $CSR ]; then
    echo "$(basename $0): Invalid CSR"
    exit 1
fi
if [ -z $CRT ]; then
    echo "$(basename $0): Invalid CRT"
    exit 1
fi


openssl ca \
    -config $CONFIG \
    -keyfile $CA_KEY \
    -in $CSR \
    -out $CRT
