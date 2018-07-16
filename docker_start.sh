#!/usr/bin/env bash

usage()
{
    echo ""
    echo "$(basename $0): N_CONTAINERS"
    echo ""
    echo "Start the docker compose file that is runnin in the current directory."
    echo ""
    echo "N_CONTAINERS          Number of dev containers to run."
    echo ""
    echo "Separate containers may be launched for building, running the server,"
    echo "and running the client."
}

if [ $# -lt 1 ]; then
    echo "$(basename $0): Too few arguments"
    usage
    exit 1
fi

N_CONTAINERS="$1"
docker-compose up --detach --scale dev=$N_CONTAINERS
