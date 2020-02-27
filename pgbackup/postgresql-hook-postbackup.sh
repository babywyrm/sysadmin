#!/bin/bash

INFILES="$@"
OUTFILE="/tmp/dbdumps-$HOSTNAME-$(date +%Y%m%d-%H%M%S).tgz.aes"

tar czpf - $INFILES | openssl aes-256-cbc -salt -out "$OUTFILE"

echo $OUTFILE

############
##
##
###########################################
