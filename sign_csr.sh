#!/usr/bin/env bash

# Prerequisites: these (specified by the corresponding .cnf file) must exist:
#   new_certs_dir
#   index.txt (must be empty or OpenSSL will silently fail)
#   serial.txt, with a valid serial number in hex: xx

#https://www.sslshopper.com/article-most-common-openssl-commands.html
#https://www.shellhacks.com/decode-csr/

# Hard-coded/assumed to be in the .cnf file
KEYS_DIR=keys
NEW_CERTS_DIR=certs

usage ()
{
    echo ""
    echo "$(basename $0) [CA_CERT] [CA_KEY] [CONFIG] [CSR] [CERT]"
    echo ""
    echo "Sign a Certificate Signing Request using a Certifate Authority's self-signed certificate"
    echo ""
    echo "Sign a CSR using the CA's private key. Read device's (not CA's) config, input a device's CSR, output a new CERT for the device."
}

if [ $# -lt 5 ]; then
    echo "$(basename $0): Too few arguments"
    usage
    exit 1
fi

if [ $# -gt 5 ]; then
    echo "$(basename $0): Too many arguments"
    usage
    exit 1
fi

CA_CERT="$1"
CA_KEY="$2"
CONFIG="$3"
CSR="$4"
CERT="$5"

if [ -z $CA_CERT ]; then
    echo "$(basename $0): Invalid CA_CERT"
    exit 1
fi
if [ -z $CA_KEY ]; then
    echo "$(basename $0): Invalid CA_KEY"
    exit 1
fi
if [ -z $CONFIG ]; then
    echo "$(basename $0): Invalid CONFIG"
    exit 1
fi
if [ -z $CSR ]; then
    echo "$(basename $0): Invalid CSR"
    exit 1
fi
if [ -z $CERT ]; then
    echo "$(basename $0): Invalid CERT"
    exit 1
fi

# Certificates can also be created using 'openssl x509 -req'
# combined with the options -CA, -CAkey, -set_serial

# -batch        Do not prompt user for input
# -notext       Do not print the plaintext form of the certificate in the output file
openssl ca \
    -batch \
    -cert $CA_CERT \
    -keyfile $CA_KEY \
    -keyform PEM \
    -config $CONFIG \
    -in $CSR \
    -notext \
    -out $CERT

if [ $? -ne 0 ]; then
    echo "Failed to generate certificate!"
    exit 1
fi

echo "Generated certificate $CERT"
echo "Also placed key cert in $KEYS_DIR/$NEW_CERTS_DIR/$(cat keys/serial.txt).pem"
