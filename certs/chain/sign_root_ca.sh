#!/usr/bin/env bash

openssl req \
    -config ../config/root_ca.cnf \
    -new \
    -key private/root_ca_key.pem \
    -out root/root_ca_cert.pem
