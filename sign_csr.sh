#!/usr/bin/env bash

# Notice!
# Prerequisites: these (specified by the corresponding .cnf file) must exist:
#   new_certs_dir
#   index.txt (must be empty or OpenSSL will silently fail)
#   serial.txt, with a valid serial number in hex: xx
#
# Run:
#   mkdir <keys_dir>/<new_certs_dir>
#   touch <keys_dir>/index.txt
#   echo '00' > <keys_dir>/serial.txt
#
#NOTE I've moved several options into the config file.

#https://www.sslshopper.com/article-most-common-openssl-commands.html
#https://www.shellhacks.com/decode-csr/

usage ()
{
    echo ""
    echo "$(basename $0) [CA_CONFIG] [CA_EXTENSIONS] [CSR] [CRT]"
    echo ""
    echo "Sign a Certificate Signing Request using a Certifate Authority's self-signed certificate"
    echo ""
    echo "Sign a CSR using the CA's private key. Read device's (not CA's) config, input a device's CSR, output a new CERT for the device."
}

NUM_ARGS=4
if [ $# -lt $NUM_ARGS ]; then
    echo "$(basename $0): Too few arguments"
    usage
    exit 1
fi

if [ $# -gt $NUM_ARGS ]; then
    echo "$(basename $0): Too many arguments"
    usage
    exit 1
fi

CA_CONFIG="$1"
CA_EXTENSIONS="$2"
CSR="$3"
CERT="$4"

if [ -z $CA_CONFIG ]; then
    echo "$(basename $0): Invalid CA_CONFIG"
    exit 1
fi
if [ -z $CA_EXTENSIONS ]; then
    echo "$(basename $0): Invalid CA_EXTENSIONS"
    exit 1
fi
if [ -z $CSR ]; then
    echo "$(basename $0): Invalid CSR"
    exit 1
fi
if [ -z $CRT ]; then
    echo "$(basename $0): Invalid CRT"
    exit 1
fi

# Certificates can also be created using 'openssl x509 -req'
# combined with the options -CA, -CAkey, -set_serial
# Use 'openssl req' instead to keep this similar to demonstrations.

# -batch        Do not prompt user for input
# -notext       Do not print the plaintext form of the certificate in the output file
# -cert         Signing CA cert. Specified in config file.
# -keyfile      Signing CA private key. Specified in config file.
openssl ca \
    -batch \
    -notext \
    -config $CA_CONFIG \
    -in $CSR \
    -out $CRT

if [ $? -ne 0 ]; then
    echo "Failed to generate certificate!"
    exit 1
fi

echo "Generated certificate $CRT"
echo "$(basename $CRT)"
#TODO get the basename of this
# echo "Also placed key cert in $KEYS_DIR/$NEW_CERTS_DIR/$(cat keys/serial.txt).pem"
