#!/usr/bin/env bash

openssl req \
    -out intermediate/server_localhost.csr \
    -new \
    -keyout intermediate/server_localhost_key.pem \
    -config config/server_localhost.cnf
