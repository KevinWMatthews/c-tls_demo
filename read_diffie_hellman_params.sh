#!/usr/bin/env bash

usage ()
{
    echo ""
    echo "Read Diffie-Hellman parameters from file"
    echo ""
    echo "$(basename $0) [INPUT_FILE]"
    echo ""
}

FILENAME="$1"

if [ -z $FILENAME ]; then
    echo "$(basename $0): Must specify input filename"
    usage
    exit 1
fi

openssl dhparam -check -in $FILENAME -text
