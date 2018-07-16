#!/usr/bin/env bash

usage()
{
    echo ""
    echo "$(basename $0)"
    echo ""
    echo "Stop the docker compose file that is runnin in the current directory."
    echo ""
}

docker-compose down
