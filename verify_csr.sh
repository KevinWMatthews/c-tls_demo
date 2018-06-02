#!/usr/bin/env bash

usage ()
{
    echo ""
    echo "Verify Certificate Signing Request"
    echo ""
    echo "$(basename $0) [OPTION] ... [CSR]"
    echo ""
    echo "Options:"
    echo "  --print-key     Print the contents of the public key"
    echo "  --print-csr     Print the contents of the CSR"
    echo ""
}

CSR=
PRINT_KEY="-noout"      # Do not print by default
PRINT_CSR=""

if [ $# -eq 0 ]; then
    echo "$(basename $0): Too few arguments"
    usage
    exit 1
fi

POSITIONAL_ARGS=()
while [ $# -gt 0 ]; do
    arg="$1"
    case $arg in
        --print-key)
            PRINT_KEY=""
            shift
            ;;
        --print-csr)
            PRINT_CSR="-text"
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        -*)
            echo "$(basename $0): Unrecognized option: $arg"
            usage
            exit 1
            ;;
        *)
            POSITIONAL_ARGS+=($arg)
            shift
            ;;
    esac
done

if [ "${#POSITIONAL_ARGS[@]}" -gt 1 ]; then
    echo "$(basename $0): Too many arguments: ${POSITIONAL_ARGS[@]}"
    usage
    exit 1
fi

set -- "${POSITIONAL_ARGS[@]}"

CSR="$1"
if [ -z $CSR ]; then
    echo "$(basename $0): CSR may not be empty"
    exit 1
fi

openssl req \
    -verify \
    $PRINT_KEY \
    $PRINT_CSR \
    -in $CSR
