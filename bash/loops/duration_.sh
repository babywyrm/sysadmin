#!/bin/bash
##

## Script Start
START=$(date +%s)

## Total Runtime
DURATION=$((60 * 60 * 24))

## Total running time
UPTIME=$(($(date +%s) - $START))

while [[ $UPTIME < $DURATION ]]; do

    ## Logic here...
    echo -n "Time remaining: "
    echo $(($DURATION - $UPTIME))

    ## Night-Night
    sleep 2

    ## Update Runtime
    UPTIME=$(($(date +%s) - $START))

done

#################
##
##
