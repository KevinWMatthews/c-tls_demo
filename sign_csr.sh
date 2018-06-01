#!/usr/bin/env bash

#https://www.sslshopper.com/article-most-common-openssl-commands.html
#https://www.shellhacks.com/decode-csr/

usage ()
{
    echo ""
    echo "Sign a Certificate Signing Request using a Certifate Authority's self-signed certificate"
    echo ""
    echo "$(basename $0) [CONFIG] [CSR] [KEY] [CRT]"
    echo ""
}
