#!/usr/bin/env bash

usage ()
{
    echo ""
    echo "Verify a private key"
    echo ""
    echo "$(basename $0) [OPTION] [KEY]"
    echo ""
    echo "Options:"
    echo "  --print-key     Print the contents of the private key"
    echo ""
}

KEY=
PRINT_KEY="-noout"      # Silence by default

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

set -- "${POSITIONAL_ARGS[@]}"

KEY="$1"

openssl rsa \
    -check \
    $PRINT_KEY \
    -in $KEY
