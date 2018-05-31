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

CERT_NAME="$1"
PRINT_PEM="-noout"      # Prints by default; must silence
PRINT_CRT=""            # Silent by default


if [ -z $CERT_NAME ]; then
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
            POSITIONAL_ARGS+=("$1")
            shift
            ;;
    esac
done

# -noout    do not print public key
# -text     print certificate contents
openssl x509 -in $CERT_NAME $PRINT_PEM $PRINT_CRT
