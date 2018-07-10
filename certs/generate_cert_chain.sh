#!/usr/bin/env bash

cat intermediate/intermediate_ca_cert.pem root/root_ca_cert.pem > intermediate/ca_chain_cert.pem
