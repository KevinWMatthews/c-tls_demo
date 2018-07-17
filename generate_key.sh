#!/usr/bin/env bash


usage ()
{
    echo ""
    echo "Generate an AES key"
    echo ""
    echo "$(basename $0) [FILENAME] [BITS]"
    echo ""
    echo "Options:"
    echo "  FILENAME        Output filename"
    echo "  BITS            Number of bits in resulting key"
    echo ""
    echo "Typically 2048 bits are used for certificates and 4096 (?) bits are used for certificate authorities"
    echo ""
}

FILENAME=
BITS=""

if [ $# -lt 2 ]; then
    echo "$(basename $0): Too few arguments"
    usage
    exit 1
fi
if [ $# -gt 2 ]; then
    echo "$(basename $0): Too many arguments"
    usage
    exit 1
fi

FILENAME="$1"
if [ -z $FILENAME ]; then
    echo "$(basename $0): Invalid filename"
    exit 1
fi

BITS="$2"
if [ -z $BITS ]; then
    echo "$(basename $0): Invalid number of bits"
    exit 1
fi

openssl genrsa \
    -aes256 \
    -out $FILENAME \
    $BITS
