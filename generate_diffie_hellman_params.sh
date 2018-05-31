#!/usr/bin/env bash

usage ()
{
    echo ""
    echo "Generate file with parameters for Diffie-Hellman key exchange"
    echo ""
    echo "$(basename $0) [OUTPUT_FILE]"
    echo ""
}

FILENAME="$1"

if [ -z $FILENAME ]; then
    echo "$(basename $0): Must specify output filename"
    usage
    exit 1
fi

# -text         Output human-readable parameters as well
openssl dhparam -check -5 -out $FILENAME 1024
