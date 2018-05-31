#!/usr/bin/env bash

CERT_DIR=keys
CERT_NAME="$1"

if [ -z $CERT_NAME ]; then
    echo "$(basename $0): Must enter cert name"
    exit 1
fi

# -noout    do not print public key contents
# -text     print certificate contents
openssl x509 -in $CERT_DIR/$CERT_NAME -text -noout
