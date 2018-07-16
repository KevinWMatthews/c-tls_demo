#!/usr/bin/env bash

usage()
{
    echo ""
    echo "$(basename $0): CONTAINER_NUMBER COMMAND [OPTIONS]"
    echo ""
    echo "Run the given command in the specified container."
    echo ""
    echo "CONTAINER_NUMBER      The 1-based index of the container."
    echo "                      Identical containers are spawned using docker-compose with the basename '$(basename $(pwd)).'"
    echo "COMMAND               The command to run in the container."
    echo "OPTIONS               Options for the command. Optional (hence the name)."
    echo ""
}

if [ $# -lt 2 ]; then
    echo "$(basename $0): Too few arguments"
    usage
    exit 1
fi

USER_ID=$(id --user)
USER_GROUP=$(id --group)
# Working directory in container - location of bind mount for build directory.
# Specified in docker-compose.yml
WORKDIR=/home/build_tls_demo

CONTAINER_BASE=$(basename $(pwd))       # This is the Docker default
SERVICE="dev"                           # From the docker-compose file
CONTAINER_NUMBER="$1"
CONTAINER_NAME="${CONTAINER_BASE}_${SERVICE}_${CONTAINER_NUMBER}"
shift

docker exec \
    --interactive \
    --tty \
    --user $USER_ID:$USER_GROUP \
    --workdir $WORKDIR \
    $CONTAINER_NAME \
    $@
