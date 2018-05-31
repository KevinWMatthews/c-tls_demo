#!/usr/bin/env bash

usage ()
{
    echo ""
    echo "Generate self-signed certificate"
    echo ""
    echo "$(basename $0) [KEY] [CONFIG]"
    echo ""
    echo "TODO convert this to use actual options"
    echo ""
}

KEY_NAME="$1"
CONFIG_NAME="$2"

if [ -z $KEY_NAME ]; then
    echo "$(basename $0): Must specify key/cert"
    usage
    exit 1
fi

if [ -z $CONFIG_NAME ]; then
    echo "$(basename $0): Must specify config file"
    usage
    exit 1
fi


openssl req \
    -new \
    -x509 \
    -days 1095 \
    -config $CONFIG_NAME \
    -keyout $KEY_NAME.pem \
    -out $KEY_NAME.crt
