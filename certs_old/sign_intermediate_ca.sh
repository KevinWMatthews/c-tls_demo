#!/usr/bin/env bash

# He uses the config of the root ca??
openssl ca \
    -config config/intermediate_ca.cnf \
    -notext \
    -cert root/root_ca_cert.pem \
    -keyfile root/root_ca_key.pem \
    -in intermediate/intermediate_ca.csr \
    -out intermediate/intermediate_ca_cert.pem
