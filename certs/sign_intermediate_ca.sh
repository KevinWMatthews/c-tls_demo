#!/usr/bin/env bash

#config of root ca??
openssl ca \
    -config config/root_ca.cnf \
    -notext \
    -cert root/root_ca_cert.pem \
    -keyfile root/root_ca_key.pem \
    -in intermediate/intermediate_ca.csr \
    -out intermediate/intermediate_ca_cert.pem
