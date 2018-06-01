#!/usr/bin/env bash

usage ()
{
    echo ""
    echo "Read Certificate Signing Request"
    echo ""
    echo "$(basename $0) [CSR]"
    echo ""
    echo "TODO add options"
    echo ""
}

CSR="$1"

if [ -z $CSR ]; then
    echo "$(basename $0): Invalid CSR"
    exit 1
fi

#TODO make -noout default, add option to override
openssl req \
    -verify \
    -in $CSR
