#!/usr/bin/env bash

openssl ca \
    -config config/server_localhost.cnf \
    -notext \
    -in intermediate/server_localhost.csr \
    -out intermediate/server_localhost_cert.pem
