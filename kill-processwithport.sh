#!/bin/bash

#fuser $1/tcp
OUTPUT="$(fuser $1/tcp)"
#OUTPUT="$(ls -l)"
# Why OUTPUT only store the process id ?
echo "$OUTPUT"
kill $OUTPUT


