#!/usr/bin/env bash

usage ()
{
    echo ""
    echo "Usage: $(basename $0) [OPTION] ... CSR"
    echo ""
    echo "Verify a Certificate Signing Request (CSR)"
    echo ""
    echo "Options:"
    echo "  --print-pem         Print the contents of the public key"
    echo "  --print-csr         Print the contents of the Certificate Signing Request"
    echo ""
}

CSR_NAME="$1"
PRINT_PEM="-noout"      # Prints by default; must silence
PRINT_CSR=""            # Silent by default

if [ -z $CSR_NAME ]; then
    echo "$(basename $0): Must specify CSR"
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
            exit 0
            ;;
        *)
            POSITIONAL_ARGS+=("$1")
            shift
            ;;
    esac
done

# -noout    do not print public key
# -text     print the csr contents
# -verify   verify the csr
openssl req -in $CSR_NAME $PRINT_PEM $PRINT_CSR -verify
