#!/usr/bin/env bash

usage ()
{
    echo ""
    echo "Usage: $(basename $0) [OPTION] ... CERT"
    echo ""
    echo "Read a Certificate"
    echo ""
    echo "Options:"
    echo "  --print-pem     Print the contents of the public key"
    echo "  --print-crt     Print the contents of the certificate"
    echo ""
}

CERT_NAME=
PRINT_PEM="-noout"      # Prints by default; must silence
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
        --print-pem)
            PRINT_PEM=""
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

CERT_NAME=${POSITIONAL_ARGS[0]}

# -noout    do not print public key
# -text     print certificate contents
openssl x509 -in $CERT_NAME $PRINT_PEM $PRINT_CRT
