#!/usr/bin/env bash

KEY_DIR=keys
KEY_NAME="$1"

if [ -z $KEY_NAME ]; then
    echo "$(basename $0): Must enter name for key/cert"
    exit 1
fi

# CSR           Certificate Signing Request
# -text         Print verbose certificate request details to output file
# -subject      Print certificate request subject line to output file
# -pubkey       Print public key to output file (and private key...)
openssl req \
    -new \
    -keyout $KEY_DIR/$KEY_NAME.pem \
    -out $KEY_DIR/$KEY_NAME.csr
