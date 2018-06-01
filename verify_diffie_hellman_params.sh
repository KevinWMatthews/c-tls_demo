#!/usr/bin/env bash

usage ()
{
    echo ""
    echo "Verify Diffie-Hellman parameters"
    echo ""
    echo "$(basename $0) [OPTION] ... [INPUT_FILE]"
    echo ""
    echo "Options:"
    echo "  --print-pem         Print DH parameters in PEM form"
    echo "  --print-params      Print DH params in human-readable form"
    echo ""
}

INPUT_FILE=
PRINT_PEM="-noout"
PRINT_PARAMS=

if [ $# -eq 0 ]; then
    echo "$(basename $0): Too few arguments"
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
        --print-params)
            PRINT_PARAMS="-text"
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

INPUT_FILE="$1"
if [ -z $INPUT_FILE ]; then
    echo "$(basename $0): INPUT_FILE may not be empty"
    usage
    exit 1
fi

openssl dhparam \
    -check \
    $PRINT_PEM \
    $PRINT_PARAMS \
    -in $INPUT_FILE
