#!/usr/bin/env bash

usage ()
{
    echo ""
    echo "Usage: $(basename $0) [OPTION] ... CERT"
    echo ""
    echo "Read a Certificate"
    echo ""
    echo "Options:"
    echo "  --print-key     Print the contents of the public key"
    echo "  --print-crt     Print the contents of the certificate"
    echo ""
}

CERT=
PRINT_KEY="-noout"      # Prints by default; silence unless overridden by user
PRINT_CRT=""            # Silent by default


if [ $# -eq 0 ]; then
    echo "$(basename $0): Must specify certificate name"
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
        --print-crt)
            PRINT_CRT="-text"
            shift
            ;;
        -*)
            echo "$(basename $0): Unrecognized option: $arg"
            usage
            exit 0
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

CERT=${POSITIONAL_ARGS[0]}
if [ -z $CERT ]; then
    echo "$(basename $0): CERT may not be empty"
    exit 1
fi

openssl x509 \
    $PRINT_KEY \
    $PRINT_CRT \
    -in $CERT

# The x509 command is silent on success.
if [ $? -eq 0 ]; then
    echo "Verify OK"
fi
