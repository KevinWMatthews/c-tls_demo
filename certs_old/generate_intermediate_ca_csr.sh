#!/usr/bin/env bash

openssl req \
    -new \
    -config config/intermediate_ca.cnf \
    -keyout intermediate/intermediate_ca_key.pem \
    -out intermediate/intermediate_ca.csr
