#!/usr/bin/env bash

#config of root ca??
openssl ca \
    -config config/root_ca.cnf \
    -notext \
    -in intermediate/intermediate_ca.csr \
    -out intermediate/intermediate_ca_cert.pem
