#!/usr/bin/env bash

openssl s_client \
    -showcerts \
    -servername $1 \
    --connect $1:10002
