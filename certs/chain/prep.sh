#!/usr/bin/env bash

# Details are specified by root_ca.cnf
mkdir newcerts
mkdir private
mkdir intermediate
mkdir root

touch root/index.txt
#TODO Only if file doesn't exist
echo '00' > root/serial.txt
