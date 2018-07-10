#!/usr/bin/env bash

# Details are specified by root_ca.cnf
mkdir newcerts
mkdir private
mkdir intermediate
mkdir root

#TODO Only if file doesn't exist
# touch root/index.txt
# echo '00' > root/serial.txt

touch intermediate/index.txt
echo '00' > intermediate/serial.txt
