#!/bin/bash
##
##
##  __examine_for_viability_
##
###########################################
#####
#####
# Author: Andrew Howard

while read LINE; do
  for ALLOCATION in $LINE; do
    CIDR=`echo $ALLOCATION | sed s/^.*"\/"//`
    NUMIPS=`echo "2^(32-$CIDR)-3" | bc`
    BASE=`echo $ALLOCATION | sed s/^".*\..*\..*\."// | sed s/"\/"$CIDR//`
    EXTC=`echo $ALLOCATION | sed s/$BASE"\/"$CIDR//`
    GATEWAY=$EXTC$(($BASE+1))
    NETMASK=255.255.255.$((253-$NUMIPS))

    for x in `seq 1 $NUMIPS`; do
      echo "clear ip arp $EXTC$(($BASE+1+$x))"
    done
  done
done

##########################################
