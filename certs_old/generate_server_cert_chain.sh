#!/usr/bin/env bash

# Me hoping for the best

cat intermediate/server_localhost_cert.pem intermediate/intermediate_ca_cert.pem root/root_ca_cert.pem > intermediate/server_chain_cert.pem
