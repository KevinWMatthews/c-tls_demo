#!/usr/bin/env bash

usage ()
{
    echo ""
    echo "Sign a Certificate Signing Request using a Certifate Authority's self-signed certificate"
    echo ""
    echo "$(basename $0) [CONFIG] [CSR] [KEY] [CRT]"
    echo ""
}
