#!/usr/bin/env bash

docker exec \
    --interactive \
    --tty \
    --user $(id --user):$(id --group) \
    --workdir /home/build_tls_demo \
    tls_demo_dev_1 \
    $@
