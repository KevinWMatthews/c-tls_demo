#!/usr/bin/env bash

KEY_DIR=generated
KEY_NAME="$1"

if [ -z $KEY_NAME ]; then
    echo "$(basename $0): Must enter name for key/cert"
    exit 1
fi

# CSR           Certificate Signing Request
openssl req \
    -new \
    -keyout $KEY_DIR/$KEY_NAME.pem \
    -out $KEY_DIR/$KEY_NAME.csr
