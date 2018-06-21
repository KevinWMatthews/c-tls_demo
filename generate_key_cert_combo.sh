#!/usr/bin/env bash

show_usage ()
{
    echo ""
    echo "Usage: $(basename $0) KEY CERT COMBO"
    echo ""
}

show_help ()
{
    echo "Combine a Certificate and Private (!) Key"
    echo ""
    echo "KEY           Path to existing private key"
    echo "CERT          Path to existing certificate"
    echo "COMBO         Path to file that will be generated"
    echo ""
    echo "This behavior seems to be unique to Asterisk's SIP channel."
    echo "Unlike their later PJSIP stack, the SIP stack does not allow"
    echo "private key and certificate files to be uploaded separately."
    echo ""
}

POSITIONAL_ARGS=()
while [ $# -gt 0 ]; do
    arg="$1"
    case $arg in
        --help)
            show_usage
            show_help
            exit 0
            ;;
        -*)
            echo "Unrecognized argument: $arg"
            show_usage
            show_help
            exit 1
            ;;
        *)
            POSITIONAL_ARGS+=($arg)
            echo $arg
            shift
            ;;
    esac
done

set -- "${POSITIONAL_ARGS[@]}"

if [ $# -lt 3 ]; then
    echo "$(basename $0): Too few arguments"
    show_usage
    exit 1
fi
if [ $# -gt 3 ]; then
    echo "$(basename $0): Too many arguments"
    show_usage
    exit 1
fi

KEY=$1
CERT=$2
COMBO=$3

if [ -z "$KEY" ]; then
    echo "$(basename $0): KEY may not be empty"
    exit 1
fi
if [ -z "$CERT" ]; then
    echo "$(basename $0): CERT may not be empty"
    exit 1
fi
if [ -z "$COMBO" ]; then
    echo "$(basename $0): COMBO may not be empty"
    exit 1
fi

cat $KEY > $COMBO
./verify_crt.sh $CERT --print-key >> $COMBO
