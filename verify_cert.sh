#!/usr/bin/env bash

# -trusted
# -verify_hostname localhost \
    # -CAfile certs/root/root_ca_cert.pem \
    # -verbose \
    # -partial_chain \
    #  certs/intermediate/intermediate_ca_cert.pem
# -trusted
command="openssl verify \
    -show_chain \
    -CAfile certs/intermediate/server_chain_cert.pem certs/root/root_ca_cert.pem \
    certs/intermediate/server_localhost_cert.pem"

echo $command
$command
