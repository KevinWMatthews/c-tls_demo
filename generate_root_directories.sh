#!/usr/bin/env bash

usage ()
{
    echo ""
    echo "Create directories and database for root certificate"
    echo ""
    echo "$(basename $0) CERT_DIR"
    echo ""
    echo "Options:"
    echo "  CERT_ROOT            Root directory for all certificates"
    echo ""
}

if [ $# -eq 0 ]; then
    echo "$(basename $0): Too few arguments"
    usage
    exit 1
fi
if [ $# -gt 1 ]; then
    echo "$(basename $0): Too many arguments"
    usage
    exit 1
fi

CERT_ROOT="$1"
if [ -z "$CERT_ROOT" ]; then
    echo "$(basename $0): Invalid argument"
    usage
    exit 1
fi

mkdir -p $CERT_ROOT
mkdir -p $CERT_ROOT/root_ca
mkdir -p $CERT_ROOT/root_ca/new_certs
touch $CERT_ROOT/root_ca/index.txt
touch $CERT_ROOT/root_ca/index.txt.attr
echo '00' > $CERT_ROOT/root_ca/serial.txt
